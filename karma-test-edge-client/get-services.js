
import {ZitiBrowzerCore} from "../dist/esm/index.js";



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
      controllerApi: 'https://curt-controller:1280',
      updbUser: 'admin',
      updbPswd: 'admin',
    });
    expect(zitiContext).to.not.equal(undefined);

    await zitiContext.initialize();

    let zitiBrowzerEdgeClient = zitiContext.createZitiBrowzerEdgeClient({
        domain: 'https://curt-controller:1280',
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

    let id = zitiContext.getServiceIdByName('curt-mattermost-dark');
    console.log('id is: ', id);
    expect(id).to.not.equal(undefined);

    let encryptionRequired = zitiContext.getServiceEncryptionRequiredByName('curt-mattermost-dark');
    console.log('encryptionRequired is: ', encryptionRequired);
    expect(encryptionRequired).to.not.equal(undefined);
    expect(encryptionRequired).to.equal(false);

    let networkSession = await zitiContext.getNetworkSessionByServiceId(id);
    console.log('networkSession is: ', networkSession);
    expect(networkSession).to.not.equal(undefined);
  

  });

});

