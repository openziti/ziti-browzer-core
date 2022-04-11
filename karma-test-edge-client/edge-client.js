
import {ZitiBrowzerCore} from "../dist/esm/index.js";

// var updbUser = window.__env__['ZITI_EDGE_CLIENT_TESTS_USER'];
// var updbPswd = window.__env__['ZITI_EDGE_CLIENT_TESTS_PSWD'];
var updbUser = 'curt';
var updbPswd = 'browzer!';


describe("test-edge-client", function () {
  this.timeout(5000);

  beforeEach(async function () {
    this.zitiBrowzerCore = new ZitiBrowzerCore();
    this.logger = this.zitiBrowzerCore.createZitiLogger({
      logLevel: 'Trace',
      suffix: 'test-edge-client'
    });

  });

  it("get Controller version", async function () {
    let zitiContext = this.zitiBrowzerCore.createZitiContext({
      logger: this.logger,
      controllerApi: 'https://ziti-edge-controller:1280',
      updbUser: updbUser,
      updbPswd: updbPswd,
    });
    expect(zitiContext).to.not.equal(undefined);

    await zitiContext.initialize();

    let zitiBrowzerEdgeClient = zitiContext.createZitiBrowzerEdgeClient({
        domain: 'https://ziti-edge-controller:1280',
        logger: this.logger
    });
    expect(zitiBrowzerEdgeClient).to.not.equal(undefined);

    let res = await zitiBrowzerEdgeClient.listVersion();
    let controllerVersion = res.data.version;
    console.log('controllerVersion is: ', controllerVersion);
    expect(controllerVersion).to.not.equal(undefined);

    let token = await zitiContext.getFreshAPISession();
    console.log('token is: ', token);
    expect(token).to.not.equal(undefined);



  });

});

