"use strict";

/**
 * Produktor main manager
 */
window.Produktor = new function() {
    $.extend(this, EventDispatcher);

    let Produktor = this;
    let isCPanel = $('html').hasClass('cpanel');

    Produktor.translations = null;

    /**
     * Translate and/or get value
     */
    Produktor.trans = function(key, lid, translations, dontFilter) {
        let keys = key ? key.split('.') : undefined;
        let fid = Produktor.translations.fallbackId;
        let value = undefined;
        let firstLevel = translations === undefined;

        lid = lid ? lid : 'hybrid'; //Produktor.translations.currentId;
        translations = translations ? translations : Produktor.translations.list[lid];

        if(!key) {
            return translations;
        }

        if(translations.hasOwnProperty(keys[0])) {
            if(keys.length === 1) {
                return translations[keys[0]];
            } else if(typeof translations[keys[0]] === 'object') {
                value = Produktor.trans(keys.slice(1).join('.'), lid, translations[keys[0]], dontFilter)
            }
        }

        // Fallback
        if(value === undefined && firstLevel && lid !== fid) {
            value = Produktor.trans(key, fid, undefined, dontFilter);
        }

        // Filter strings
        if(typeof value === 'string' && !dontFilter) {
            value = value.replace(/\n/g, '<br/>');
        }

        return value;
    };

    /**
     * Evaluate translation by key
     *
     * @param key
     */
    Produktor.evalTrans = function(key) {
        return eval(Produktor.trans(key, undefined, undefined, true));
    };

    /**
     * API request method
     *
     * @ctrl {string} Control name
     * @act {string} API Method name
     * @data {object} Mixed request data
     * */
    Produktor.query = function(ctrl, act, request) {
        if(!request) {
            request = {}
        }
        return $.ajax({
            url:      "api.php",
            dataType: "json",
            data:     {
                ctrl: ctrl,
                act:  act,
                data: request
            }
        }).always(function() {
        })
    };

    /**
     * Open modal dialog
     * Returns XHR
     * After load xhr.modal is HTML dialog jquery element.
     */
    Produktor.modal = function(templateName, request) {
        let xhr = Produktor.query('template', 'modal', $.extend({name: templateName}, request)).done(function(html) {
            let el = $(html);
            let name = 'modal-' + Math.round(Math.random() * 1000000000);

            xhr.el = el;
            el.attr('name', name);

            $('body').append(el);

            let view = el.parent().find('.modal[name="' + name + '"]');

            view.on("hidden.bs.modal", function() {
                view.modal('dispose');
                view.off();
                el.remove();
                el.off();
            }).modal();

            view.data('request', request);

            if(view.attr('onload')) {
                eval(view.attr('onload'));
            }

        });
        return xhr;
    };

    /**
     * Load view by name and request
     *
     * Returns XHR
     */
    Produktor.loadView = function(name, request) {
        return Produktor.query('template', 'view', $.extend({name: name}, request));
    };

    /**
     * Wallet manager
     */
    Produktor.wallets = new function() {
        let wallets = this;
        let networks = {
            BTC:  {
                messagePrefix: '\x18Bitcoin Signed Message:\n',
                bip32:         {
                    public:  0x0488b21e,
                    private: 0x0488ade4
                },
                pubKeyHash:    0x00,
                scriptHash:    0x05,
                wif:           0x80,
                float:         1e8
            },
            Produktor: {
                messagePrefix: '\x19DarkCoin Signed Message:\n',
                bip32:         {
                    public:  0x02fe52f8,
                    private: 0x02fe52cc
                },
                pubKeyHash:    0x4c,
                scriptHash:    0x10,
                wif:           0xcc,
                dustThreshold: 5460, // https://github.com/dashpay/dash/blob/v0.12.0.x/src/primitives/transaction.h#L144-L155
                float:         1e8
            },
            LCC:  {
                messagePrefix: '\x19Litecoin Signed Message:\n',
                bip32:         {
                    public:  0x019da462,
                    private: 0x019d9cfe
                },
                pubKeyHash:    28,
                scriptHash:    5,
                float:         1e8,
                hashType:      (bitcoin.js.Transaction.SIGHASH_ALL | bitcoin.js.Transaction.SIGHASH_BITCOINCASHBIP143),
                wif:           176
            },
            DASH: {
                messagePrefix: '\x19DarkCoin Signed Message:\n',
                bip32:         {
                    public:  0x02fe52f8,
                    private: 0x02fe52cc
                },
                pubKeyHash:    0x4c,
                scriptHash:    0x10,
                wif:           0xcc,
                float:         1e8,
                dustThreshold: 5460 // https://github.com/dashpay/dash/blob/v0.12.0.x/src/primitives/transaction.h#L144-L155
            }
        };

        /**
         * Import wallet
         *
         * @param {Object} args
         */
        wallets.import = function(args) {
            let chainName = args.chain;
            let wallet;

            if(chainName === 'ETH') {
                let pk = args.pk;

                switch (args.ethFrom) {

                    case 'fromPrivateKey': {
                        if(pk.length === 64) {
                            pk = '0x' + pk;
                        }
                        wallet = ethereum.wallet.fromPrivateKey(ethereum.util.toBuffer(pk));
                        break;
                    }

                    case 'fromExtendedPrivateKey': {
                        wallet = ethereum.wallet.fromExtendedPrivateKey(ethereum.util.toBuffer(pk));
                        break;
                    }

                    case 'fromMnemonic': {
                        let hdWallet = ethereum.hdKey.fromMasterSeed(ethereum.bip39.mnemonicToSeed(pk));
                        let path = "m/44'/60'/0'/0/0";
                        wallet = hdWallet.derivePath(path).getWallet();
                        break;
                    }

                    case 'fromV3': {
                        wallet = ethereum.wallet.fromV3(ethereum.util.toBuffer(pk), args.password);
                        break;
                    }

                    case 'fromV1': {
                        wallet = ethereum.wallet.fromV1(ethereum.util.toBuffer(pk), args.password);
                        break;
                    }

                    case 'fromEthSale': {
                        wallet = ethereum.wallet.fromEthSale(ethereum.util.toBuffer(pk), args.password);
                        break;
                    }

                    //  import a wallet generated by EtherWallet
                    case 'fromEtherWallet': {
                        wallet = ethereum.thirdParty.fromEtherWallet(args.input, args.password);
                        break;
                    }

                    // import a brain wallet used by Ether.Camp
                    case 'fromEtherCamp': {
                        wallet = ethereum.thirdParty.fromEtherWallet(pk);
                        break;
                    }

                    //  import a wallet from a KryptoKit seed
                    case 'fromKryptoKit': {
                        wallet = ethereum.thirdParty.fromEtherWallet(args.seed);
                        break;
                    }

                    //  import a brain wallet used by Quorum Wallet
                    case 'fromQuorumWallet': {
                        wallet = ethereum.thirdParty.fromEtherWallet(args.password, args.userid);
                        break;
                    }
                }
            } else {
                if(!networks.hasOwnProperty(chainName)) {
                    Produktor.error('No network info! Extend! :)');
                }
                wallet = bitcoin.js.ECPair.fromWIF(args.pk, networks[chainName]);
            }
            wallet.chain = chainName;
            return wallet;
        };

        /**
         * Generate new wallet
         *
         * @param chainName
         */
        wallets.create = function(chainName) {
            let wallet;

            if(chainName === 'ETH') {
                wallet = ethereum.wallet.generate();
            } else {
                let params = {};
                if(!networks.hasOwnProperty(chainName)) {
                    Produktor.error('No network info! Extend! :)');
                    return null;
                }
                params = {network: networks[chainName]};
                wallet = bitcoin.js.ECPair.makeRandom(params);
            }

            wallet.chain = chainName;
            return wallet;
        };

        /**
         * Create transaction builder
         *
         * @param chainName
         * @return {tx} Transaction
         */
        wallets.createTx = function(chainName) {

            if(!networks.hasOwnProperty(chainName)) {
                Produktor.error('No network info! Extend! :)');
            }

            return new bitcoin.js.TransactionBuilder(networks[chainName]);
        };

        /**
         * Create custom TX
         *
         * @param chain
         * @param walletFrom
         * @param walletPK
         * @param toAddress
         * @param amount
         * @param {String||undefined} fee (optional)
         * @param {String||undefined} description
         * @param {Array|undefined} productIds (optional) Product ID's
         * @return {string} transaction as HEX
         *
         * @todo: add fee and save description in blockchain as JSON. :)
         */
        Produktor.customTx = function(chain, walletFrom, walletPK, toAddress, amount, fee, description) {
            if (!walletFrom || !walletPK) {
                Produktor.notify('Please fill wallets data', {type: 'danger'});
                return;
            }
            if (!chain || !toAddress || !amount) {
                Produktor.notify('Please try again or contact the administration', {type: 'danger'});
                return;
            }
            let utxoSum = 0;
            let utxoArr = [];
            let tx = wallets.createTx(chain);
            if (!fee) {
                fee = tx.maximumFeeRate;
            }
            let xhr = Produktor.wallets.getAddressInfo(chain, walletFrom).done(function(info) {
                if (info.balance < amount) {
                    Produktor.error('Not enough coins or wrong wallets credentials');
                    return;
                }
                let utxo = info.last_txs;
                utxo.forEach(function (value) {
                    if (utxoSum - amount > fee) {
                        return;
                    }
                    utxoSum += value.value;
                    utxoArr.push(value);
                });

                let key = bitcoin.js.ECPair.fromWIF(walletPK, tx.network);
                utxoArr.forEach(function (value) {
                    tx.addInput(value.tx_hash, value.tx_pos);
                });
                let hashType = bitcoin.js.Transaction.SIGHASH_ALL | bitcoin.js.Transaction.SIGHASH_BITCOINCASHBIP143;
                tx.addOutput(toAddress, amount);
                tx.addOutput(walletFrom, utxoSum - amount - fee);
                let counter = 0;
                utxoArr.forEach(function (value) {
                    tx.sign(counter, key, null, hashType, 0);
                    counter++;
                });
                let signedTx = tx.build();

                let answer = Produktor.query('wallet', 'pushTx', {
                    chain: chain,
                    txHex: signedTx.toHex()
                }).done(function(res) {
                    let result = JSON.parse(res);
                    console.log(result);
                    if (result.status) {
                        Produktor.notify('Successful payment<br>Transaction Id:'+result.txId);
                    } else {
                        Produktor.notify('Unsuccessful payment, please try again or contact administration', {type: 'danger'})
                    }

                });
            });
            xhr.tx = tx;
            return xhr;
        };

        /**
         * Create, sign and push custom ethereum TX
         *
         * @param {String} walletFrom
         * @param {String} walletPK
         * @param {String} toAddress
         * @param {Number} amount
         * @param {Number|undefined} fee
         * @param {String|undefined} description
         * @param {Function} onComplete
         * @return {string} transaction as HEX
         *
         * @todo: add fee and save description in blockchain as JSON. :)
         */
        wallets.createSignAndPushEthTx = function(walletFrom, walletPK, toAddress, amount, fee, description, onComplete) {
            let web3 = new ethereum.web3;
            let utils = web3.utils;

            web3.setProvider(new web3.providers.HttpProvider('https://api.myetherapi.com/eth'));

            let xhr = Produktor.query('wallet', 'getFee', {chain: 'ETH'}).done(function(gasPriceHex) {
                let tx = new ethereum.tx({
                    nonce:    utils.toHex(web3.eth.getTransactionCount(walletFrom)),
                    gasPrice: gasPriceHex,
                    gasLimit: utils.toHex(200000),
                    to:       toAddress,
                    value:    utils.toHex(parseInt(utils.toWei(amount.toString(), 'ether'))),
                    data:     '0x00',
                    chainId:  utils.toHex(web3.version.network)
                });

                tx.sign(new ethereum.buffer.Buffer(walletPK.replace(/^0x/, ''), 'hex'));

                xhr.tx = tx;
                xhr.pushXhr = Produktor.query('wallet', 'pushTx', {
                    chain:  'ETH',
                    from:   walletFrom,
                    to:     toAddress,
                    amount: amount,
                    fee:    fee,
                    tx:     '0x' + tx.serialize().toString('hex')
                }).done(function(result) {

                    if(result.errors) {
                        Produktor.error('Unsuccessful payment, please try again or contact administration');
                        _.each(result.errors, function(error) {
                            Produktor.error(error);
                        });
                        return;
                    }

                    if(onComplete) {
                        onComplete(result, tx, xhr.pushXhr);
                    }

                    Produktor.notify('Successful payment<br>Transaction Id:' + result.tx);
                });
            });

            return xhr;
        };

        /**
         * Create custom ethereum TX
         *
         * @param walletFrom
         * @param walletPK
         * @param toAddress
         * @param amount
         * @param fee
         * @param description
         * @return {string} transaction as HEX
         *
         * @todo: add fee and save description in blockchain as JSON. :)
         */
        ethereum.customTx = function(walletFrom, walletPK, toAddress, amount, fee, description) {
            let web3 = new ethereum.web3;
            web3.setProvider(new web3.providers.HttpProvider('https://api.myetherapi.com/eth'));
            amount = parseInt(web3.utils.toWei(amount, 'ether'));
            let gasLimit = web3.utils.toHex(200000);
            let privateKeyHex = new ethereum.buffer.Buffer(walletPK, 'hex');
            let answer = Produktor.query('wallet', 'getGasPrice', {
            }).done(function(res) {
                res = JSON.parse(res);
                let gasPriceHex = res.price;
                let nonce = web3.eth.getTransactionCount(walletFrom);
                let nonceHex = web3.utils.toHex(nonce);
                const rawTx = {
                    nonce:    nonceHex,
                    gasPrice: gasPriceHex,
                    gasLimit: gasLimit,
                    to:       toAddress,
                    value:    web3.utils.toHex(amount),
                    data:     '0x00',
                    chainId:  web3.utils.toHex(web3.version.network)
                };

                let tx = new ethereum.tx(rawTx);
                tx.sign(privateKeyHex);
                let signedTx = tx.serialize();
                let answer = Produktor.query('wallet', 'pushTx', {
                    chain: 'ETH',
                    txHex: '0x' + signedTx.toString('hex')
                }).done(function(res) {
                    let result = JSON.parse(res);
                    if (result.status) {
                        Produktor.notify('Successful payment<br>Transaction Id:'+result.txId);
                    } else {
                        Produktor.notify('Unsuccessful payment, please try again or contact administration', {type: 'danger'})
                    }

                });

            });
            return true;
        };

        /**
         * Get address info
         *
         * @param {String} chainName
         * @param {String} address
         */
        wallets.getAddressInfo = function(chainName, address){
            return Produktor.query('wallet', 'address', {
                addr:  address,
                chain: chainName
            });
        };

        /**
         * Returns all unspent outputs for an address.
         *
         * @param {String} chainName
         * @param {String} address
         */
        wallets.listUnspent = function(chainName, address) {
            return Produktor.query('wallet', 'listUnspent', {
                addr:  address,
                chain: chainName
            });
        };
    };

    /**
     * User API
     *
     */
    Produktor.user = new function() {

        $.extend(this, EventDispatcher);

        let user = this;

        user.data = null;

        /**
         * Register user
         *
         * @param formData
         */
        user.register = function(formData) {
            return Produktor.query('user', 'register', formData).done(function(user) {
                if(user.errors.length) {
                    Produktor.dispatch('userRegisterErrors', user);
                } else {
                    Produktor.dispatch('userRegistered', user);
                }
            })
        };

        /**
         * Open user register modal dialog
         *
         * @returns {XMLHttpRequest}
         */
        user.modalRegister = function(args) {
            args = typeof args !== 'undefined' ? args : {useBase: false};
            let xhr = Produktor.modal('register', args);

            xhr.done(function() {
                let form = $('form', xhr.el);
                form.find("[type='submit']").on('click', function() {
                    let data = form.formData();
                    // $('> fieldset', form).attr('disabled', 'disabled');
                    Produktor.user.register(data);
                    return false;
                })
            });

            return xhr;
        };

        /**
         * Open user forgot password modal dialog
         *
         * @returns {XMLHttpRequest}
         */
        user.modalForgotPassword = function(args) {
            return Produktor.modal('forgotPassword', args);
        };

        /**
         * Open user login modal dialog
         *
         * @returns {XMLHttpRequest}
         */
        user.modalLogin = function(args) {
            let xhr = Produktor.modal('login').done(function(r) {
                let form = $('form', xhr.el);
                $('.submit', form).on('click', function() {
                    Produktor.query('user', 'login', form.formData()).done(function(r) {
                        if(r.errors) {
                            _.each(r.errors, function(error) {
                                Produktor.notify(error.message);
                            });
                        }else{
                            let user = r;
                            // Produktor.notify('Welcome ' + user.name + '!');
                            // Produktor.user.data = user;
                            // Produktor.rebuildTopNavigation();
                            // xhr.el.modal('hide');
                            // Produktor.dispatch('userLoggedIn', user);
                            location.href = 'cpanel.php';
                        }
                    });
                    return false;
                });
            });
            return xhr;
        };

        /**
         * Open user login modal dialog
         *
         * @returns {XMLHttpRequest}
         */
        user.getData = function(callback) {
            Produktor.query('user', 'getData').done(function(user) {
                Produktor.user.data = user;
                callback(user)
            });
        };

        /**
         * Is user logged in?
         * @returns {boolean}
         */
        user.isLogged = function() {
            return !!Produktor.user.data;
        };

        /**
         * Login user
         *
         */
        user.logout = function() {
            return Produktor.query('user', 'logout').done(function(r) {
                Produktor.notify('See you soon!');
                Produktor.user.data = null;
                Produktor.rebuildTopNavigation();
            })
        };

        /**
         * User own wallets
         */
        user.wallets = new function() {

            let userWallets = this;

            /**
             *
             * @param walletId
             * @param toAddress
             * @param amount
             * @param fee
             * @param description
             * @return {string} transaction as HEX
             *
             * @todo save description in blockchain as JSON. :)
             */
            userWallets.send = function(walletId, toAddress, amount, fee, description) {
                let wallet = userWallets.list()[walletId];
                let chain = wallet.chain;
                let walletFrom = wallet.pb;
                let tx = Produktor.wallets.createTx(chain);
                let key = bitcoin.js.ECPair.fromWIF(wallet.pk, tx.network);
                let float = tx.network.float ? tx.network.float : 1e8;
                let hashType = tx.network.hasOwnProperty('hashType') ? tx.network.hashType : undefined;

                fee = fee !== undefined || fee !== null ? tx.maximumFeeRate : fee;

                // Todo: estimated right fee
                fee = tx.maximumFeeRate;

                if(!walletFrom || !toAddress || !amount) {
                    Produktor.notify('Please fill wallets data', {type: 'danger'});
                    return;
                }

                let xhr = Produktor.wallets.listUnspent(chain, walletFrom).done(function(utxs) {
                    let balanceSatoshi = _.sumBy(utxs, 'satoshis');
                    let amountSatoshi = amount * float;
                    let balance = balanceSatoshi / float;

                    if(balanceSatoshi < amountSatoshi) {
                        Produktor.error('Not enough coins or wrong wallets credentials');
                        return;
                    }

                    let uTxSum = 0;
                    let satoshisNeeded = (amountSatoshi + fee);
                    let restSatoshis = 0;
                    let usedUTxs = [];

                    _.each(utxs, function(uTx) {
                        let restNeeded = (satoshisNeeded - uTxSum);

                        if(restNeeded <= 0) {
                            return;
                        }

                        if(uTx.satoshis <= restNeeded) {
                            uTxSum += uTx.satoshis;
                        } else {
                            restSatoshis = uTx.satoshis - restNeeded;
                            uTxSum += restNeeded;
                        }

                        tx.addInput(uTx.txid, uTx.outputIndex);
                        usedUTxs.push(usedUTxs);
                    });

                    tx.addOutput(toAddress, satoshisNeeded);
                    tx.addOutput(walletFrom, restSatoshis);

                    _.each(usedUTxs, function(utx, i) {
                        if(hashType) {
                            tx.sign(i, key, null, hashType, 0);
                        } else {
                            tx.sign(i, key);
                        }
                    });

                    let signedTxHex = tx.build().toHex();

                    xhr.pushXhr = Produktor.query('wallet', 'pushTx', {
                        to:     toAddress,
                        from:   walletFrom,
                        amount: amount,
                        tx:    signedTxHex,
                        fee:   fee,
                        chain: chain
                    }).done(function(r) {
                        if(r.errors) {
                            _.each(r.errors, function(error) {
                                Produktor.notify(error.message);
                            });
                        } else {
                            console.log(r);
                        }
                    });
                });

                return xhr;
            };

            /**
             * List user wallets.
             *
             * Notice: If there no wallets, but user is logged in,
             * wallets will be created at once and pk's stored in browser only.
             *
             * @return {null|Array} Wallet list
             */
            userWallets.list = function() {

                // Create initial wallets
                if(!user.isLogged()) {
                    console.log("What about user login?");
                    return null;
                }

                let walletsOldStorageKey = 'wallets';
                let walletsStoreKey = walletsOldStorageKey + user.data.user_id;
                let hasPreviousWallets = store.get(walletsOldStorageKey) !== undefined;
                let hasWallets = store.get(walletsStoreKey) !== undefined;

                if(hasPreviousWallets && !hasWallets) {
                    // Migrate wallets to new storage place
                    store.set(walletsStoreKey, store.get(walletsOldStorageKey));
                    // Remove old storage
                    store.set(walletsOldStorageKey, undefined);

                    _.each(store.get(walletsStoreKey), function(wallet) {
                        Produktor.query('user', 'addWallet', {
                            title: wallet.title,
                            chain: wallet.coinName,
                            pb:    wallet.pb
                        });
                    })
                } else if(!hasWallets) {
                    // Initial wallets creation
                    store.set(walletsStoreKey, _.map(['Produktor', 'LCC', 'BTC', 'DASH', 'ETH'], function(chain) {
                        let wallet = Produktor.wallets.create(chain);
                        let xhr = userWallets.add(wallet, chain + " #1", true);
                        let pk;

                        if(wallet.chain === 'ETH') {
                            pk = wallet.getPrivateKeyString()
                        } else {
                            pk = wallet.toWIF();
                        }

                        return _.extend({pk: pk}, xhr.info);
                    }));

                    // TODO: move this out from
                    Produktor.cPanel.loadPage('buy-token');
                }

                return store.get(walletsStoreKey);
            };

            /**
             * Add user wallet and store to DB
             *
             * @param wallet
             * @param title
             * @param dontStoreLocaly dont store, but sent address to server.
             */
            userWallets.add = function(wallet, title, dontStoreLocaly) {
                let pk;
                let info = {
                    title: title,
                    chain: wallet.chain,
                };

                if(wallet.chain === 'ETH') {
                    info.pb = wallet.getAddressString();
                    info.pubKey = wallet.getPublicKeyString();
                    info.checkSum = wallet.getChecksumAddressString();
                    pk = wallet.getPrivateKeyString()
                } else {
                    info.pb = wallet.getAddress();
                    pk = wallet.toWIF();
                }

                let xhr = Produktor.query('user', 'addWallet', info);
                xhr.info = info;

                if(!dontStoreLocaly) {
                    let wallets = userWallets.list();
                    wallets.push(_.extend({pk: pk}, info));
                    store.set('wallets' + user.data.user_id, wallets);
                    // TODO: move this out from
                    Produktor.cPanel.loadPage('buy-token');
                }

                return xhr;
            };

            /**
             * Open export wallet modal
             *
             * @param id
             */
            userWallets.openExportModal = function(id) {
                let wallet = userWallets.list()[id];
                let xhr = Produktor.modal('wallet/export').done(function(r) {
                    let el = xhr.el;
                    el.find('.wallet-title').text(wallet.title + ' (' + wallet.chain + ')');
                    el.find('[name="pk"]').val(wallet.pk);

                    new QRCode(el.find('.qr-pk-export')[0], {
                        text:   wallet.pk,
                        width:  200,
                        height: 200
                    });
                })
            };

            /**
             * Remove user wallet
             *
             * @param id
             */
            userWallets.remove = function(id) {
                let wallets = userWallets.list();
                let wallet = userWallets.list()[id];

                return swal({
                    title:              'Are you sure?',
                    html:               "Once deleted, you will not be able to recover the wallet!<br/>" + "<span style='font-weight: bold; margin-top: 20px'>" + wallet.chain + ":" + wallet.pb + "</span>",
                    type:               'warning',
                    showCancelButton:   true,
                    confirmButtonText:  'Yes, delete it!',
                    cancelButtonText:   'No, cancel!',
                    confirmButtonClass: 'btn btn-success',
                    cancelButtonClass: 'btn btn-danger',
                    buttonsStyling:    false,
                    reverseButtons:    true,
                    onClose:           function() {
                        // swal('Cancelled', 'Your imaginary wallet is safe :)', 'success');
                    }
                }).then(function(result) {
                    if(result) {
                        Produktor.query('user', 'removeWallet', {
                            pb: wallet.pb
                            // pk: wallet.pk
                        }).done(function(r) {
                            wallets.splice(id, 1);
                            store.set('wallets' + user.data.user_id, wallets);
                            wallet.removed = true;
                            swal('Deleted!', "Poof! Your imaginary wallet has been deleted!", 'success')
                        });

                    } else {
                        swal('Cancelled', 'Your imaginary wallet is safe :)', 'success')
                    }
                });

            };

            /**
             * Open deposit modal
             * @param id
             */
            userWallets.openDepositModal = function(id) {
                return Produktor.modal('wallet/deposit', {id: id})
            };

            userWallets.openWithdrawModal = function(id) {
                return Produktor.modal('wallet/withdraw', {id: id});
            };
        };
    };

    /**
     * Shop API
     *
     * @todo: Implement and bind shop templates
     */
    Produktor.shop = new function() {
        let shop = this;
        shop.add = function(product, shopId) {
        };
        shop.remove = function(productId) {
        };
        shop.get = function(product, shopId) {
        };
        shop.list = function(shopId) {
        };
    };

    /**
     * Generate navigation
     */
    Produktor.generateNavigation = function() {
        let mainNavigation = $(".main-navigation");
        let list = Produktor.translations.list[translations.currentId];

        mainNavigation.empty();
        $.each(list.menu, function(k, v) {
            let isObject = typeof v !== 'string';
            let item = $('<li/>')
                .addClass('nav-item')
                .css('user-select', 'none')
                .append($('<a/>')
                    .addClass('nav-link')
                    .attr('href', '#' + k)
                    .html(v));

            mainNavigation.append(item);
        });
    };

    /**
     * Rebuild top navigtion depends on user data
     */
    this.rebuildTopNavigation = function() {
        if(Produktor.user.isLogged()) {
            $('.logout-item').show(0);
            $('.cpanel-item').show(0);
            $('.login-item').hide(0);
        } else {
            $('.logout-item').hide(0);
            $('.cpanel-item').hide(0);
            $('.login-item').show(0);
        }
    };

    /**
     * Buy tokens modal check
     */
    Produktor.buyTokens = function() {
        if(Produktor.user.isLogged()) {
            location.href = 'cpanel.php#buy-token';
        } else {
            Produktor.notify("In order to buy tokens you need to login<br/>or register you self!");
            Produktor.user.modalRegister();
        }
    };

    /**
     * Notify
     *
     * @param message
     * @param args
     */
    Produktor.notify = function(message, args) {
        $.notify({
            icon:    args && args.icon ? args.icon : "notifications",
            message: message
        }, $.extend({
            type:  'success',
            timer: 500,
            animate: {
                enter: 'animated fadeInDown',
                exit: 'animated fadeOutUp'
            },
            template: '<div data-notify="container" class="col-xs-10 col-sm-2 alert alert-{0}" role="alert" style="border-radius: 5px; background-color: #3170bf; opacity: 0.5">' +
                      '<button type="button" aria-hidden="true" class="close" data-notify="dismiss">×</button>' +
                      '<span data-notify="icon"></span> ' +
                      '<span data-notify="title">{1}</span> ' +
                      '<span data-notify="message">{2}</span>' +
                      '<div class="progress" data-notify="progressbar">' +
                      '<div class="progress-bar progress-bar-{0}" role="progressbar" aria-valuenow=c"0" aria-valuemin="0" aria-valuemax="100" style="width: 0%;"></div>' +
                      '</div>' +
                      '<a href="{3}" target="{4}" data-notify="url"></a>' +
                      '</div>'
        }, args));
    };

    /**
     * Notify error
     *
     * @param message
     * @param args
     */
    Produktor.error = function(message, args) {
        args = args || {};
        args.type = 'error';
        Produktor.notify(message, args);
    };

    // On Loads
    $(function() {
        // Get all translations
        Produktor.query('translation', 'list').done(function(_translations) {
            Produktor.translations = _translations;

            let cid = Produktor.translations.currentId;
            let fid = Produktor.translations.fallbackId;

            // Merge and clone object as new copy of the structure
            Produktor.translations.list.hybrid = cid === fid ? _.extend({}, Produktor.translations.list[fid]) : _.defaultsDeep(_.extend({}, Produktor.translations.list[cid]), Produktor.translations.list[fid]);

            // Get user data and load page custom JS
            Produktor.user.getData(function() {

                if(isCPanel) {
                    $.getScript("assets/js/cpanel.js");
                } else {
                    $.getScript("assets/js/Produktor.js");
                }
            });
        });
    });
};
