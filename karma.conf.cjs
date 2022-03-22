module.exports = function(config) {
  
  let cryptoTests = {
    type: "module",
    pattern: "karma-test-crypto/*.js"
  };
  let edgeClientTests = {
    type: "module",
    pattern: "karma-test-edge-client/*.js"
  };

  let files = [];

  files.push(cryptoTests);
  if (process.env.ZITI_EDGE_CLIENT_TESTS) {
    files.push(edgeClientTests);
  }

  config.set(
    {
      
      frameworks: [
        'mocha', 
        'chai', 
        'esm'
      ],
      
      files: files,
      
      reporters: ['progress'],
      
      port: 9876,  // karma web server port
      
      colors: true,

      logLevel: config.LOG_INFO,
      
      browsers: [
        'ZitiHeadlessChrome'
      ],
      
      customLaunchers: {

        ZitiHeadlessChrome: {
          base: 'ChromeHeadless',
          displayName: 'ZitiHeadlessChrome',
          flags: [
            '--disable-translate', 
            '--disable-extensions', 
            '--remote-debugging-port=9222'
          ]
        },

      },
  
      autoWatch: false,

      singleRun: true, // Karma captures browsers, runs the tests and exits
      
      concurrency: Infinity,

      plugins: [
        require.resolve('@open-wc/karma-esm'),  // make ESM work    
        'karma-*',  // fallback: resolve any karma- plugins
      ],
    
      esm: {
        nodeResolve: true,
      },
    
    }
  )
}
  