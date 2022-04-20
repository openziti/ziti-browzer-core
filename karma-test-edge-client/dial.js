
import {ZitiBrowzerCore} from "../dist/esm/index.js";

// var updbUser = window.__env__['ZITI_EDGE_CLIENT_TESTS_USER'];
// var updbPswd = window.__env__['ZITI_EDGE_CLIENT_TESTS_PSWD'];
var updbUser = 'curt';
var updbPswd = 'browzer!';


describe("dial", function () {
  this.timeout(5000);

  beforeEach(async function () {
    this.zitiBrowzerCore = new ZitiBrowzerCore();
    this.logger = this.zitiBrowzerCore.createZitiLogger({
      logLevel: 'Trace',
      suffix: 'dial'
    });

  });

  it("Dial Services", async function () {
    console.log('window.__env__ is: ', window.__env__);

    let zitiContext = this.zitiBrowzerCore.createZitiContext({
      logger: this.logger,
      controllerApi: 'https://ziti-edge-controller:1280',
      updbUser: updbUser,
      updbPswd: updbPswd,
    });
    expect(zitiContext).to.not.equal(undefined);

    await zitiContext.initialize();

    let conn = zitiContext.newConnection();
    expect(conn).to.not.equal(undefined);
    expect(conn.zitiContext).to.equal(zitiContext);

    await zitiContext.dial(conn, 'mattermost-blue');

    let expiryTime = await zitiContext.getCertPEMExpiryTime();
    expect(expiryTime).to.not.equal(undefined);

  });

});

