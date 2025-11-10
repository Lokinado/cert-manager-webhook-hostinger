package main

import (
	"os"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"github.com/cert-manager/webhook-example/internal/hostinger"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	// Uncomment the below fixture when implementing your custom DNS provider
	hostingerSolver := hostinger.New()
	// fixture := acmetest.NewFixture(hostingerSolver,
	// 	acmetest.SetResolvedZone(zone),
	// 	acmetest.SetAllowAmbientCredentials(false),
	// 	acmetest.SetManifestPath("testdata/hostinger"),
	// )

	fixture := acmetest.NewFixture(hostingerSolver,
		acmetest.SetResolvedZone("example.com"), // Change this to your hostinger domain
		acmetest.SetManifestPath("testdata/hostinger"),
		acmetest.SetDNSServer("ns1.dns-parking.com:53"), // make sure that dns is correct
		acmetest.SetUseAuthoritative(false),
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
