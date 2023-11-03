'use strict';

const path = require('path');
const fs = require('fs').promises;
const express = require('express');
const expressSession = require('express-session');
const debug = require('debug')('Server');

const Util = require('./Util');
const ServerError = require('./ServerError');
const WireGuard = require('../services/WireGuard');
const { RELEASE } = require('../package.json');
const WG_CONFIG = require('../config');
const PORT = process.env.PORT || 51821;
const PASSWORD = process.env.PASSWORD;
const WGCONFIG = new WG_CONFIG();

module.exports = class Server {

    constructor() {
        // Express
        this.app = express()
            .disable('etag')
            .use('/', express.static(path.join(__dirname, '..', 'www')))
            .use(express.json())
            .use(expressSession({
                secret: String(Math.random()),
                resave: true,
                saveUninitialized: true,
            }))

            .get('/api/release', (Util.promisify(async () => {
                return RELEASE;
            })))

            // Authentication
            .get('/api/session', Util.promisify(async req => {
                const requiresPassword = !!process.env.PASSWORD;
                const authenticated = requiresPassword
                    ? !!(req.session && req.session.authenticated)
                    : true;

                return {
                    requiresPassword,
                    authenticated,
                };
            }))
            .post('/api/session', Util.promisify(async req => {
                const {
                    password,
                } = req.body;

                if (typeof password !== 'string') {
                    throw new ServerError('Missing: Password', 401);
                }

                if (password !== PASSWORD) {
                    throw new ServerError('Incorrect Password', 401);
                }

                req.session.authenticated = true;
                req.session.save();

                debug(`New Session: ${req.session.id}`);
            }))

            // WireGuard
            .use((req, res, next) => {
                if (!PASSWORD) {
                    return next();
                }

                if (req.session && req.session.authenticated) {
                    return next();
                }

                return res.status(401).json({
                    error: 'Not Logged In',
                });
            })
            .delete('/api/session', Util.promisify(async req => {
                const sessionId = req.session.id;
                req.session.destroy();
                debug(`Deleted Session: ${sessionId}`);
            }))
            .get('/api/tunnel/client', Util.promisify(async req => {
                return WireGuard.getClients();
            }))
            .get('/api/tunnel/client/:clientId/qrcode.svg', Util.promisify(async (req, res) => {
                const { clientId } = req.params;
                const svg = await WireGuard.getClientQRCodeSVG({ clientId });
                res.header('Content-Type', 'image/svg+xml');
                res.send(svg);
            }))
            .get('/api/tunnel/client/:clientId/configuration', Util.promisify(async (req, res) => {
                const { clientId } = req.params;
                const client = await WireGuard.getClient({ clientId });
                const config = await WireGuard.getClientConfiguration({ clientId });
                const configName = client.name
                    .replace(/[^a-zA-Z0-9_=+.-]/g, '-')
                    .replace(/(-{2,}|-$)/g, '-')
                    .replace(/-$/, '')
                    .substring(0, 32);
                res.header('Content-Disposition', `attachment; filename="${configName || clientId}.conf"`);
                res.header('Content-Type', 'text/plain');
                res.send(config);
            }))
            .get('/api/tunnel/client/:clientId/config', Util.promisify(async (req, res) => {
                const { clientId } = req.params;
                const config = await WireGuard.getClientConfiguration({ clientId });
                res.send({config:config});
            }))
            .post('/api/tunnel/client', Util.promisify(async req => {
                const { name } = req.body;
                return WireGuard.createClient({ name });
            }))
            .delete('/api/tunnel/client/:clientId', Util.promisify(async req => {
                const { clientId } = req.params;
                return WireGuard.deleteClient({ clientId });
            }))
            .post('/api/tunnel/client/:clientId/enable', Util.promisify(async req => {
                const { clientId } = req.params;
                return WireGuard.enableClient({ clientId });
            }))
            .post('/api/tunnel/client/:clientId/disable', Util.promisify(async req => {
                const { clientId } = req.params;
                return WireGuard.disableClient({ clientId });
            }))
            .put('/api/tunnel/client/:clientId/name', Util.promisify(async req => {
                const { clientId } = req.params;
                const { name } = req.body;
                return WireGuard.updateClientName({ clientId, name });
            }))
            .put('/api/tunnel/client/:clientId/address', Util.promisify(async req => {
                const { clientId } = req.params;
                const { address } = req.body;
                return WireGuard.updateClientAddress({ clientId, address });
            }))
            .get('/api/tunnel/prot', Util.promisify(async req => {
                return { 
                    port: await WGCONFIG.get("WG_PORT"),
                    ports: (await WGCONFIG.get("WG_PORTS")),
                    history_ports: (await WGCONFIG.get("WG_HISTORY_PORT"))
                }
            }))
            .put('/api/tunnel/prot', Util.promisify(async req => {
                var { prot } = req.body;
                var WG_PORT = await WGCONFIG.get("WG_PORT")
                var WG_PORTS = (await WGCONFIG.get("WG_PORTS")).split("-")
                var WG_HISTORY_PORT = await WGCONFIG.get("WG_HISTORY_PORT")
                WG_HISTORY_PORT.push(WG_PORT);
                if(prot && prot != WG_PORT){
                    if(prot >= WG_PORTS[0] && prot <=  WG_PORTS[0]){
                        await fs.writeFile(path.join((await WGCONFIG.get('WG_PATH')),'wg_config.json'), JSON.stringify({
                            WG_PORT: prot,
                            WG_HISTORY_PORT: WG_HISTORY_PORT,
                        }, false, 2), {
                            mode: 0o660,
                        });
                        WireGuard.saveConfig()
                    }
                }else if(!prot && WG_PORTS[1]){
                    prot = 0
                    for (let index = WG_PORTS[0]; index < WG_PORTS[1]; index++) {
                        if(WG_HISTORY_PORT.indexOf(index) == -1){
                            prot = index;
                            break;
                        }
                    }
                    if(prot){
                        await fs.writeFile(path.join((await WGCONFIG.get('WG_PATH')),'wg_config.json'), JSON.stringify({
                            WG_PORT: prot,
                            WG_HISTORY_PORT: WG_HISTORY_PORT,
                        }, false, 2), {
                            mode: 0o660,
                        });
                        WireGuard.saveConfig()
                    }
                }
                return { prot: prot }
            }))
            .delete('/api/tunnel/prot', Util.promisify(async req => {
                await fs.writeFile(path.join((await WGCONFIG.get('WG_PATH')),'wg_config.json'), JSON.stringify({
                    WG_PORT: 0,
                    WG_HISTORY_PORT: [],
                }, false, 2), {
                    mode: 0o660,
                });
                WireGuard.saveConfig()
                return { prot: 0 }
            }))
            .listen(PORT, () => {
                debug(`Listening on http://0.0.0.0:${PORT}`);
            });
    }

};
