// optionally try to use compiled ursa generation
try {
  var ursa = require('ursa');
}catch(E){}

var forge = require('node-forge');

module.exports = function(opts, cb) {
  if (typeof opts == 'function') cb = opts;
  if (typeof opts != 'object') opts = {};
  if (typeof opts.bits == 'undefined') opts.bits = 2048;
  if (typeof opts.e == 'undefined') opts.e = 65537;
  
  if (!opts.purejs)
  {
    try {
      var pair = ursa.generatePrivateKey(opts.bits, opts.e);
      var pubKey =  pair.toPublicSsh('base64');
      var keypair = {
        public: 'ssh-rsa ' + pubKey,
        private: pair.toPrivatePem('utf8'),
        fingerprint: ursa.sshFingerprint(pubKey, 'base64', 'hex')
      };
    }catch(E){}
    // bad form to cb from inside a try
    if(keypair) return cb(null, keypair);
  }
  forge.rsa.generateKeyPair(opts, function(err, pair){
    if (err) return cb(err);
    var keypair = {
      public: forge.ssh.publicKeyToOpenSSH(pair.publicKey),
      private: forge.ssh.privateKeyToOpenSSH(pair.privateKey),
      fingerprint: forge.ssh.getPublicKeyFingerprint(pair.publicKey, { encoding: 'hex' })
    };
    cb(null, keypair);
  });
};
