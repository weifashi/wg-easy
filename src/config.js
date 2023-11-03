'use strict';

const fs = require('fs').promises;
const path = require('path');

module.exports = class WGCONFIG {

    async get(key)  {
        const WG_PATH = process.env.WG_PATH || '/etc/wireguard/';
        var WG_PORT = process.env.WG_PORT || 51820;
        var WG_HISTORY_PORT = [];
        try {
            var wgConfig = await fs.readFile(path.join(WG_PATH, 'wg_config.json'), 'utf8');
            wgConfig = JSON.parse(wgConfig);
            if(wgConfig.WG_PORT){
                WG_PORT = wgConfig.WG_PORT
            }
            if(wgConfig.WG_HISTORY_PORT){
                WG_HISTORY_PORT = wgConfig.WG_HISTORY_PORT
            }
        } catch (err) {
            // eslint-disable-next-line no-console
        }
        const config = {
            WG_PATH: WG_PATH,
            WG_DEVICE: process.env.WG_DEVICE || 'eth0',
            WG_HOST: process.env.WG_HOST,
            WG_PORT: WG_PORT,
            WG_PORTS: process.env.WG_PORTS || '51820-51920',
            WG_HISTORY_PORT: WG_HISTORY_PORT,
            WG_MTU: process.env.WG_MTU || null,
            WG_PERSISTENT_KEEPALIVE: process.env.WG_PERSISTENT_KEEPALIVE || 25,
            WG_DEFAULT_ADDRESS: process.env.WG_DEFAULT_ADDRESS || '10.8.0.x',
            WG_DEFAULT_DNS: typeof process.env.WG_DEFAULT_DNS === 'string' ? process.env.WG_DEFAULT_DNS : '8.8.8.8',
            WG_ALLOWED_IPS: process.env.WG_ALLOWED_IPS || '0.0.0.0/0, ::/0',
            WG_PRE_UP: process.env.WG_PRE_UP || '',
            WG_PRE_DOWN: process.env.WG_PRE_DOWN || '',
            WG_POST_DOWN: process.env.WG_POST_DOWN || '',
        };
        config.WG_POST_UP = process.env.WG_POST_UP || `
                iptables -t nat -A POSTROUTING -s ${config.WG_DEFAULT_ADDRESS.replace('x', '0')}/24 -o ${config.WG_DEVICE} -j MASQUERADE;
                iptables -A INPUT -p udp -m udp --dport ${config.WG_PORT} -j ACCEPT;
                iptables -A FORWARD -i wg0 -j ACCEPT;
                iptables -A FORWARD -o wg0 -j ACCEPT;
            `.split('\n').join(' ');

        if(key){
            return config[key]
        }

        return config;
    }

}

