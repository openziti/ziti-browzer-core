
import {ZitiBrowzerCore} from "../dist/esm/index.js";



describe("edge-client", function () {
  this.timeout(5000);

  beforeEach(async function () {
    this.zitiBrowzerCore = new ZitiBrowzerCore({logLevel: 'debug'});
  });

  it("get Controller version", async function () {
    let zitiContext = this.zitiBrowzerCore.createZitiContext({});
    expect(zitiContext).to.not.equal(undefined);

    let zitiBrowzerEdgeClient = zitiContext.createZitiBrowzerEdgeClient({
        domain: 'https://curt-controller:1280',
        logger: this.zitiBrowzerCore
    });
    expect(zitiBrowzerEdgeClient).to.not.equal(undefined);

    let res = await zitiBrowzerEdgeClient.listVersion();
    let controllerVersion = res.data.version;
    expect(controllerVersion).to.not.equal(undefined);


    // this.domain = domain ? domain : 'https://demo.ziti.dev/edge/client/v1';



    // expect(privateKeyPEM).to.not.equal(undefined);
    // expect(privateKeyPEM.startsWith('-----BEGIN PRIVATE KEY-----\n')).to.be.true;
    // expect(privateKeyPEM.endsWith('-----END PRIVATE KEY-----\n')).to.be.true;

  });

});

