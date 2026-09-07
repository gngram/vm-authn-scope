package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"grpc-app-go/echo"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type echoServer struct {
	echo.UnimplementedEchoServiceServer
	serverCN string
}

func (s *echoServer) Echo(ctx context.Context, req *echo.EchoRequest) (*echo.EchoResponse, error) {
	peerCN := "unknown"
	p, ok := peer.FromContext(ctx)
	if ok && p.AuthInfo != nil {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(tlsInfo.State.PeerCertificates) > 0 {
			peerCN = tlsInfo.State.PeerCertificates[0].Subject.CommonName
		}
	}
	logMsg("[Go App] Extracted peer name from certificate: '%s'", peerCN)
	logMsg("[Go App] Received gRPC message from '%s': %s", peerCN, req.Message)

	return &echo.EchoResponse{
		Message:      fmt.Sprintf("gRPC Echo Response from %s", s.serverCN),
		PeerIdentity: s.serverCN,
	}, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	args := os.Args[1:]
	mode := "server"
	if len(args) > 0 {
		mode = args[0]
	}
	addr := "127.0.0.1:50051"
	if len(args) > 1 {
		addr = args[1]
	}
	socketPath := "/run/authn-scope/workload.sock"
	if len(args) > 2 {
		socketPath = args[2]
	}

	logMsg("[Go App] === STEP 1: Starting Go gRPC test app (mode: '%s', target addr: '%s', socket: '%s') ===", mode, addr, socketPath)

	// Initialize official SPIFFE X509Source directly targeting the agent socket
	formattedAddr := socketPath
	if !strings.HasPrefix(socketPath, "unix:") {
		formattedAddr = "unix://" + socketPath
	}
	os.Setenv("SPIFFE_ENDPOINT_SOCKET", formattedAddr)
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(formattedAddr))

	logMsg("[Go App] === STEP 2: Connecting to SPIFFE Workload API UDS socket at '%s' ===", formattedAddr)
	var source *workloadapi.X509Source
	var err error
	for i := 0; i < 60; i++ {
		source, err = workloadapi.NewX509Source(context.Background(), clientOptions)
		if err == nil {
			logMsg("[Go App] [STEP 2 SUCCESS] Established connection to SPIFFE Workload API UDS socket on attempt %d", i+1)
			break
		}
		logMsg("[Go App] [STEP 2 ATTEMPT %d/60] Connecting to UDS at '%s' failed: %v", i+1, formattedAddr, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		logMsg("[Go App] [STEP 2 FATAL] Failed to create official SPIFFE X509Source after 60 attempts: %v", err)
		os.Exit(1)
	}
	defer source.Close()

	logMsg("[Go App] === STEP 3: Fetching initial X509SVID via SPIFFE Workload API ===")
	svid, err := source.GetX509SVID()
	if err != nil {
		logMsg("[Go App] [STEP 3 FATAL] Failed to get X509SVID from SPIFFE Workload API: %v", err)
		os.Exit(1)
	}

	cert := svid.Certificates[0]
	cn := cert.Subject.CommonName
	notBefore := cert.NotBefore.Unix()
	notAfter := cert.NotAfter.Unix()

	logMsg("[Go App] [STEP 3 SUCCESS] Initial credentials loaded! SPIFFE ID='%s', CN='%s', NotBefore=%d, NotAfter=%d",
		svid.ID.String(), cn, notBefore, notAfter)

	if mode == "server" {
		if err := runServer(addr, source, notBefore); err != nil {
			logMsg("[Go App] [SERVER FATAL] Server error: %v", err)
			os.Exit(1)
		}
	} else {
		if err := runClient(addr, source, notBefore); err != nil {
			logMsg("[Go App] [CLIENT FATAL] Client error: %v", err)
			os.Exit(1)
		}
	}
}

func runServer(addr string, source *workloadapi.X509Source, initialNotBefore int64) error {
	logMsg("[Go Server] === STEP 4: Configuring gRPC mTLS server with SPIFFE TLS Config (AuthorizeAny) ===")
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	srv := &echoServer{serverCN: "grpc-app"}
	echo.RegisterEchoServiceServer(grpcServer, srv)

	logMsg("[Go Server] [STEP 4 SUCCESS] gRPC Server listening at %s", addr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcServer.Serve(lis)
	}()

	logMsg("[Go Server] === STEP 5: Waiting 32 seconds for automatic SPIFFE SVID rotation in background... ===")
	time.Sleep(32 * time.Second)

	logMsg("[Go Server] === STEP 6: Fetching rotated X509SVID from SPIFFE SDK... ===")
	var rotatedSVID *x509svid.SVID
	var cn2 string
	var notBefore2 int64
	var notAfter2 int64

	for attempt := 0; attempt < 15; attempt++ {
		rotatedSVID, err = source.GetX509SVID()
		if err == nil && len(rotatedSVID.Certificates) > 0 {
			cert2 := rotatedSVID.Certificates[0]
			cn2 = cert2.Subject.CommonName
			notBefore2 = cert2.NotBefore.Unix()
			notAfter2 = cert2.NotAfter.Unix()
			if notBefore2 > initialNotBefore {
				break
			}
		}
		time.Sleep(1 * time.Second)
	}

	if rotatedSVID == nil || err != nil {
		return fmt.Errorf("failed to retrieve rotated SVID from official SPIFFE SDK: %w", err)
	}

	logMsg("[Go Server] [STEP 6 SUCCESS] Rotated SVID retrieved! CN='%s', NotBefore=%d, NotAfter=%d", cn2, notBefore2, notAfter2)

	if notBefore2 <= initialNotBefore {
		return fmt.Errorf("certificate timestamp verification FAILED! Initial NotBefore=%d, Rotated NotBefore=%d", initialNotBefore, notBefore2)
	}
	logMsg("[Go Server] [STEP 6 VERIFIED] Timestamp check SUCCESS! Initial NotBefore: %d, Rotated NotBefore: %d (Advanced by %ds)",
		initialNotBefore, notBefore2, notBefore2-initialNotBefore)

	logMsg("[Go Server] === STEP 7: Waiting 15 seconds for incoming gRPC client calls before graceful shutdown ===")
	time.Sleep(15 * time.Second)
	grpcServer.GracefulStop()

	logMsg("[Go Server] === STEP 8: ALL gRPC mTLS & Certificate Rotation checks PASSED successfully! ===")
	return nil
}

func runClient(addr string, source *workloadapi.X509Source, initialNotBefore int64) error {
	logMsg("[Go Client] === STEP 4: Configuring gRPC mTLS client with SPIFFE TLS Config (ServerName='grpc-app') ===")
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	tlsConfig.ServerName = "grpc-app"

	logMsg("[Go Client] === STEP 5: Pre-Rotation Connection 1 — Connecting to gRPC server at %s via mTLS ===", addr)
	var conn1 *grpc.ClientConn
	var lastErr error
	for i := 0; i < 60; i++ {
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := grpc.DialContext(dialCtx, addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
		dialCancel()
		if err == nil {
			conn1 = c
			logMsg("[Go Client] [STEP 5 SUCCESS] Connected to gRPC server at %s on attempt %d", addr, i+1)
			break
		}
		lastErr = err
		logMsg("[Go Client] [STEP 5 ATTEMPT %d/60] Pre-rotation connection attempt to %s failed: %v", i+1, addr, err)
		time.Sleep(500 * time.Millisecond)
	}
	if conn1 == nil {
		return fmt.Errorf("failed to connect to gRPC server at %s via mTLS after 60 attempts: %v", addr, lastErr)
	}

	echoClient1 := echo.NewEchoServiceClient(conn1)

	logMsg("[Go Client] === STEP 6: Sending Pre-Rotation Echo RPC request to server ===")
	ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel1()

	resp1, err := echoClient1.Echo(ctx1, &echo.EchoRequest{Message: "gRPC Hello via Official SPIFFE TLS Config (Pre-Rotation)"})
	if err != nil {
		conn1.Close()
		return fmt.Errorf("gRPC Echo call 1 failed: %w", err)
	}
	logMsg("[Go Client] [STEP 6 SUCCESS] Extracted peer identity from server cert: '%s'", resp1.PeerIdentity)
	logMsg("[Go Client] [STEP 6 SUCCESS] Received server response: '%s'", resp1.Message)
	conn1.Close()

	logMsg("[Go Client] === STEP 7: Waiting 32 seconds for background SPIFFE SVID automatic rotation... ===")
	time.Sleep(32 * time.Second)

	logMsg("[Go Client] === STEP 8: Fetching rotated X509SVID from SPIFFE SDK... ===")
	var rotatedSVID *x509svid.SVID
	var cn2 string
	var notBefore2 int64
	var notAfter2 int64

	for attempt := 0; attempt < 15; attempt++ {
		rotatedSVID, err = source.GetX509SVID()
		if err == nil && len(rotatedSVID.Certificates) > 0 {
			cert2 := rotatedSVID.Certificates[0]
			cn2 = cert2.Subject.CommonName
			notBefore2 = cert2.NotBefore.Unix()
			notAfter2 = cert2.NotAfter.Unix()
			if notBefore2 > initialNotBefore {
				break
			}
		}
		time.Sleep(1 * time.Second)
	}

	if rotatedSVID == nil || err != nil {
		return fmt.Errorf("failed to retrieve rotated SVID from official SPIFFE SDK: %w", err)
	}

	logMsg("[Go Client] [STEP 8 SUCCESS] Rotated SVID retrieved! CN='%s', NotBefore=%d, NotAfter=%d", cn2, notBefore2, notAfter2)

	if notBefore2 <= initialNotBefore {
		return fmt.Errorf("certificate timestamp verification FAILED! Initial NotBefore=%d, Rotated NotBefore=%d", initialNotBefore, notBefore2)
	}
	logMsg("[Go Client] [STEP 8 VERIFIED] Certificate timestamp verification SUCCESS! Initial NotBefore: %d, Rotated NotBefore: %d (Advanced by %ds)",
		initialNotBefore, notBefore2, notBefore2-initialNotBefore)

	logMsg("[Go Client] === STEP 9: Post-Rotation Connection 2 — Re-connecting to gRPC server at %s via SAME tlsConfig ===", addr)
	var conn2 *grpc.ClientConn
	for i := 0; i < 20; i++ {
		dialCtx2, dialCancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := grpc.DialContext(dialCtx2, addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
		dialCancel2()
		if err == nil {
			conn2 = c
			logMsg("[Go Client] [STEP 9 SUCCESS] Post-rotation connection to %s established on attempt %d", addr, i+1)
			break
		}
		lastErr = err
		logMsg("[Go Client] [STEP 9 ATTEMPT %d/20] Post-rotation connection attempt to %s failed: %v", i+1, addr, err)
		time.Sleep(500 * time.Millisecond)
	}
	if conn2 == nil {
		return fmt.Errorf("failed to connect to gRPC server post-rotation via Official SPIFFE TLS Config: %v", lastErr)
	}
	defer conn2.Close()

	logMsg("[Go Client] === STEP 10: Sending Post-Rotation Echo RPC request to server ===")
	echoClient2 := echo.NewEchoServiceClient(conn2)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	resp2, err := echoClient2.Echo(ctx2, &echo.EchoRequest{Message: "gRPC Hello via Official SPIFFE TLS Config (Post-Rotation)"})
	if err != nil {
		return fmt.Errorf("post-rotation gRPC Echo call failed: %w", err)
	}
	logMsg("[Go Client] [STEP 10 SUCCESS] Extracted post-rotation peer name: '%s'", resp2.PeerIdentity)
	logMsg("[Go Client] [STEP 10 SUCCESS] Received post-rotation response: '%s'", resp2.Message)

	logMsg("[Go Client] === STEP 11: ALL gRPC mTLS & CERTIFICATE ROTATION CHECKS PASSED SUCCESSFULLY! ===")
	return nil
}

func logMsg(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Println(msg)
	os.Stdout.Sync()
	os.Stderr.Sync()
}
