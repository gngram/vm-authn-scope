package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"grpc-app-go/echo"

	"authn-scope-workload"

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
	fmt.Printf("[Go App] Extracted peer name from certificate: '%s'\n", peerCN)
	fmt.Printf("[Go App] Received gRPC message from '%s': %s\n", peerCN, req.Message)

	return &echo.EchoResponse{
		Message:      fmt.Sprintf("gRPC Echo Response from %s", s.serverCN),
		PeerIdentity: s.serverCN,
	}, nil
}

func main() {
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

	fmt.Printf("[Go App] Starting gRPC test app in mode '%s' at %s using Production TLS Callbacks\n", mode, addr)

	client := workload.NewWorkloadClient(socketPath)

	initialCreds, err := fetchCredentialsRetry(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching initial credentials: %v\n", err)
		os.Exit(1)
	}

	// Start production background rotation loop (updates current credentials in memory automatically)
	client.StartRotationLoop(5 * time.Second)

	cn, notBefore, notAfter, err := parseCertInfo(initialCreds.CertPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate info: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[Go App] Initial credentials loaded into background rotation cache. CN='%s', NotBefore=%d, NotAfter=%d\n", cn, notBefore, notAfter)

	if mode == "server" {
		if err := runServer(addr, client, initialCreds, notBefore); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := runClient(addr, client, initialCreds, notBefore); err != nil {
			fmt.Fprintf(os.Stderr, "Client error: %v\n", err)
			os.Exit(1)
		}
	}
}

func runServer(addr string, client *workload.WorkloadClient, initialCreds *workload.X509Credentials, initialNotBefore int64) error {
	// Production Server TLS Config with dynamic GetCertificate callback
	tlsConfig, err := createDynamicTLSServerConfig(client, initialCreds)
	if err != nil {
		return fmt.Errorf("failed to create dynamic server TLS config: %w", err)
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	srv := &echoServer{serverCN: "service-b"}
	echo.RegisterEchoServiceServer(grpcServer, srv)

	fmt.Printf("[Go App] gRPC Server (google.golang.org/grpc with Production TLS Callbacks) listening at %s\n", addr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcServer.Serve(lis)
	}()

	// Wait 32 seconds while background rotation loop handles updates automatically
	fmt.Println("[Go App] Waiting 32 seconds for automatic certificate rotation threshold...")
	time.Sleep(32 * time.Second)

	// Fetch separately from Workload API ONLY for test log assertion
	assertionCreds, err := client.FetchCredentials()
	if err != nil {
		return fmt.Errorf("separate assertion fetch failed: %w", err)
	}

	cn2, notBefore2, notAfter2, err := parseCertInfo(assertionCreds.CertPEM)
	if err != nil {
		return fmt.Errorf("failed to parse assertion certificate: %w", err)
	}

	fmt.Printf("[Go App] Separate assertion fetch complete. CN='%s', NotBefore=%d, NotAfter=%d\n", cn2, notBefore2, notAfter2)

	if notBefore2 <= initialNotBefore {
		return fmt.Errorf("certificate timestamp verification FAILED! Initial NotBefore=%d, Rotated NotBefore=%d", initialNotBefore, notBefore2)
	}
	fmt.Printf("[Go App] Certificate timestamp verification SUCCESS! Initial NotBefore: %d, Rotated NotBefore: %d (Advanced by %ds)\n",
		initialNotBefore, notBefore2, notBefore2-initialNotBefore)

	time.Sleep(10 * time.Second)
	grpcServer.GracefulStop()

	fmt.Println("[Go App] All gRPC mTLS & Certificate Rotation checks PASSED successfully!")
	return nil
}

func runClient(addr string, client *workload.WorkloadClient, initialCreds *workload.X509Credentials, initialNotBefore int64) error {
	// Production Client TLS Config with dynamic GetClientCertificate callback
	tlsConfig, err := createDynamicTLSClientConfig(client, initialCreds)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client TLS config: %w", err)
	}

	// Pre-Rotation Connection 1 using Production Dynamic Callback
	var conn1 *grpc.ClientConn
	for i := 0; i < 60; i++ {
		c, err := grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
		if err == nil {
			conn1 = c
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if conn1 == nil {
		return fmt.Errorf("failed to connect to gRPC server at %s via mTLS", addr)
	}

	fmt.Printf("[Go App] Connected to gRPC server at %s via Production TLS Callbacks (Pre-Rotation Connection 1)\n", addr)
	echoClient1 := echo.NewEchoServiceClient(conn1)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel1()

	resp1, err := echoClient1.Echo(ctx1, &echo.EchoRequest{Message: "gRPC Hello via Production TLS Callback (Pre-Rotation)"})
	if err != nil {
		conn1.Close()
		return fmt.Errorf("gRPC Echo call 1 failed: %w", err)
	}
	fmt.Printf("[Go App] Extracted peer name from certificate: '%s'\n", resp1.PeerIdentity)
	fmt.Printf("[Go App] Received gRPC response: %s\n", resp1.Message)
	conn1.Close()

	// Wait 32 seconds while background rotation loop handles certificate rotation in memory
	fmt.Println("[Go App] Waiting 32 seconds for automatic certificate rotation threshold...")
	time.Sleep(32 * time.Second)

	// Separate fetch from Workload API ONLY for test assertion
	assertionCreds, err := client.FetchCredentials()
	if err != nil {
		return fmt.Errorf("separate assertion fetch failed: %w", err)
	}

	cn2, notBefore2, notAfter2, err := parseCertInfo(assertionCreds.CertPEM)
	if err != nil {
		return fmt.Errorf("failed to parse assertion certificate: %w", err)
	}

	fmt.Printf("[Go App] Separate assertion fetch complete. CN='%s', NotBefore=%d, NotAfter=%d\n", cn2, notBefore2, notAfter2)

	if notBefore2 <= initialNotBefore {
		return fmt.Errorf("certificate timestamp verification FAILED! Initial NotBefore=%d, Rotated NotBefore=%d", initialNotBefore, notBefore2)
	}
	fmt.Printf("[Go App] Certificate timestamp verification SUCCESS! Initial NotBefore: %d, Rotated NotBefore: %d (Advanced by %ds)\n",
		initialNotBefore, notBefore2, notBefore2-initialNotBefore)

	// Post-Rotation Connection 2 using THE EXACT SAME tlsConfig (GetClientCertificate automatically returns rotated cert from memory!)
	conn2, err := grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC server post-rotation via Production TLS Callbacks: %w", err)
	}
	defer conn2.Close()

	fmt.Printf("[Go App] Connected to gRPC server at %s via Production TLS Callbacks (Post-Rotation Connection 2)\n", addr)
	echoClient2 := echo.NewEchoServiceClient(conn2)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	resp2, err := echoClient2.Echo(ctx2, &echo.EchoRequest{Message: "gRPC Hello via Production TLS Callback (Post-Rotation)"})
	if err != nil {
		return fmt.Errorf("post-rotation gRPC Echo call failed: %w", err)
	}
	fmt.Printf("[Go App] Extracted post-rotation peer name: '%s'\n", resp2.PeerIdentity)
	fmt.Printf("[Go App] Received post-rotation gRPC response: %s\n", resp2.Message)

	fmt.Println("[Go App] All gRPC mTLS & Certificate Rotation checks PASSED successfully!")
	return nil
}

func createDynamicTLSServerConfig(client *workload.WorkloadClient, initialCreds *workload.X509Credentials) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(initialCreds.CaCertPEM)) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			creds := client.CurrentCredentials()
			if creds == nil {
				creds = initialCreds
			}
			cert, err := tls.X509KeyPair([]byte(creds.CertPEM), []byte(creds.KeyPEM))
			if err != nil {
				return nil, fmt.Errorf("GetCertificate error: %w", err)
			}
			return &cert, nil
		},
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func createDynamicTLSClientConfig(client *workload.WorkloadClient, initialCreds *workload.X509Credentials) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(initialCreds.CaCertPEM)) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			creds := client.CurrentCredentials()
			if creds == nil {
				creds = initialCreds
			}
			cert, err := tls.X509KeyPair([]byte(creds.CertPEM), []byte(creds.KeyPEM))
			if err != nil {
				return nil, fmt.Errorf("GetClientCertificate error: %w", err)
			}
			return &cert, nil
		},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}, nil
}

func parseCertInfo(certPEM string) (string, int64, int64, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", 0, 0, fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", 0, 0, err
	}
	cn := cert.Subject.CommonName
	if cn == "" {
		cn = "unknown"
	}
	return cn, cert.NotBefore.Unix(), cert.NotAfter.Unix(), nil
}

func fetchCredentialsRetry(client *workload.WorkloadClient) (*workload.X509Credentials, error) {
	var err error
	for i := 0; i < 40; i++ {
		creds, e := client.FetchCredentials()
		if e == nil {
			return creds, nil
		}
		err = e
		time.Sleep(500 * time.Millisecond)
	}
	return nil, fmt.Errorf("Workload API fetch credentials failed after retries: %w", err)
}
