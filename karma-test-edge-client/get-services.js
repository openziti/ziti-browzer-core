
import {ZitiBrowzerCore} from "../dist/esm/index.js";

// var updbUser = window.__env__['ZITI_EDGE_CLIENT_TESTS_USER'];
// var updbPswd = window.__env__['ZITI_EDGE_CLIENT_TESTS_PSWD'];
var updbUser = 'curt';
var updbPswd = 'browzer!';


describe("get-services", function () {
  this.timeout(5000);

  beforeEach(async function () {
    this.zitiBrowzerCore = new ZitiBrowzerCore();
    this.logger = this.zitiBrowzerCore.createZitiLogger({
      logLevel: 'Trace',
      suffix: 'get-services'
    });

  });

  it("get Services", async function () {
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

    let token = await zitiContext.getFreshAPISession();
    console.log('token is: ', token);
    expect(token).to.not.equal(undefined);

    await zitiContext.fetchServices();
    let services = zitiContext.services;
    // console.log('services is: ', services);
    expect(services).to.not.equal(undefined);

    let id = zitiContext.getServiceIdByName('mattermost-blue');
    console.log('id is: ', id);
    expect(id).to.not.equal(undefined);

    let encryptionRequired = zitiContext.getServiceEncryptionRequiredByName('mattermost-blue');
    console.log('encryptionRequired is: ', encryptionRequired);
    expect(encryptionRequired).to.not.equal(undefined);
    expect(encryptionRequired).to.equal(false);

    let networkSession = await zitiContext.getNetworkSessionByServiceId(id);
    console.log('networkSession is: ', networkSession);
    expect(networkSession).to.not.equal(undefined);
  

  });

});

