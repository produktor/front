window.bitcoin = {
    js: require('bitcoinjs-lib')
};
window.ethereum = {
    tx:         require('ethereumjs-tx'),
    util:       require('ethereumjs-util'),
    wallet:     require('ethereumjs-wallet'),
    web3:       require('web3'),
    buffer:     require('buffer'),
    bip39:      require('bip39'),
    hdKey:      require('ethereumjs-wallet/hdkey'),
    thirdParty: require('ethereumjs-wallet/thirdparty')
};

window.BigNumber = require('bignumber.js');
window.store = require('store');
