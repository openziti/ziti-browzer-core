
import {ZitiBrowzerCore} from "../dist/esm/index.js";



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
    let zitiContext = this.zitiBrowzerCore.createZitiContext({
      logger: this.logger,
      controllerApi: 'https://curt-controller:1280',
      updbUser: 'admin',
      updbPswd: 'admin',
    });
    expect(zitiContext).to.not.equal(undefined);

    await zitiContext.initialize();

    let conn = zitiContext.newConnection();
    expect(conn).to.not.equal(undefined);
    expect(conn.zitiContext).to.equal(zitiContext);

    // TODO:  the following 'dial' requires the mTLS wiring to be operational
    // await zitiContext.dial(conn, 'curt-mattermost-dark');

  });

});

