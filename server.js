import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import axios from 'axios';
import { initAuthCreds } from '@whiskeysockets/baileys';

const v = '2.24.6.77';
const vhash = crypto.createHash('md5').update(v).digest('hex');
const MOBILE_TOKEN = Buffer.from('0a1mLfGUIBVrMKF1RdvLI5lkRBvof6vn0fD2QRSM' + vhash)
const app = express();
const PROXY = 'https://y9yrsygcg6.execute-api.us-east-1.amazonaws.com';
const API_KEYS = ['xzcorpz'];
const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;
app.use(cors());
app.use(express.json());

const SECRET_KEY = Buffer.from(
    'RFObk0NHtvEmCSluaRRbWDCd+U7QqKWi2UB4qOr/hwE+' +
    'PZWmlkSqG5JGRlMsJ5+LzShVq1XyyLwWk623gAyI/w==',
    'base64'
);

const WA_CERT = Buffer.from(
    '30820332308202F0A00302010202044C2536A4300B06072A8648CE3804030500307C' +
    '310B3009060355040613025553311330110603550408130A43616C69666F726E6961' +
    '311430120603550407130B53616E746120436C61726131163014060355040A130D57' +
    '6861747341707020496E632E31143012060355040B130B456E67696E656572696E67' +
    '311430120603550403130B427269616E204163746F6E301E170D3130303632353233' +
    '303731365A170D3434303231353233303731365A307C310B30090603550406130255' +
    '53311330110603550408130A43616C69666F726E6961311430120603550407130B53' +
    '616E746120436C61726131163014060355040A130D576861747341707020496E632E' +
    '31143012060355040B130B456E67696E656572696E67311430120603550403130B42' +
    '7269616E204163746F6E308201B83082012C06072A8648CE3804013082011F028181' +
    '00FD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B651266945' +
    '5D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B76B9950' +
    'A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB83F6D3C51E' +
    'C3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C70215009760508F' +
    '15230BCCB292B982A2EB840BF0581CF502818100F7E1A085D69B3DDECBBCAB5C36B8' +
    '57B97994AFBBFA3AEA82F9574C0B3D0782675159578EBAD4594FE67107108180B449' +
    '167123E84C281613B7CF09328CC8A6E13C167A8B547C8D28E0A3AE1E2BB3A675916E' +
    'A37F0BFA213562F1FB627A01243BCCA4F1BEA8519089A883DFE15AE59F06928B665E' +
    '807B552564014C3BFECF492A0381850002818100D1198B4B81687BCF246D41A8A725' +
    'F0A989A51BCE326E84C828E1F556648BD71DA487054D6DE70FFF4B49432B6862AA48' +
    'FC2A93161B2C15A2FF5E671672DFB576E9D12AAFF7369B9A99D04FB29D2BBBB2A503' +
    'EE41B1FF37887064F41FE2805609063500A8E547349282D15981CDB58A08BEDE51DD' +
    '7E9867295B3DFB45FFC6B259300B06072A8648CE3804030500032F00302C021400A6' +
    '02A7477ACF841077237BE090DF436582CA2F0214350CE0268D07E71E55774AB4EACD' +
    '4D071CD1EFAD',
    'hex'
);

const DEX_KEY = Buffer.from('wLkgAtObV/sRW0KvCjbWPQ==', 'base64');

function genToken(phone) {
    const hmac = crypto.createHmac('sha1', SECRET_KEY);
    hmac.update(WA_CERT);
    hmac.update(DEX_KEY);
    hmac.update(phone, 'utf-8');
    return hmac.digest('base64');
}

function buildParams(phone) {
    const cc = phone.slice(0, 2);
    const national = phone.slice(2);
    const creds = initAuthCreds();
    const c201 = crypto.randomBytes(20);
    const c202 = crypto.randomBytes(20);
    const eRegid = Buffer.alloc(4);
    eRegid.writeInt32BE(creds.registrationId);

    return {
        cc,
        in: national,
        Rc: '0',
        lg: 'en',
        lc: 'GB',
        mistyped: '6',
        authkey: Buffer.from(creds.noiseKey.public).toString('base64url'),
        e_regid: eRegid.toString('base64url'),
        e_keytype: 'BQ',
        e_ident: Buffer.from(creds.signedIdentityKey.public).toString('base64url'),
        e_skey_id: 'AAAA',
        e_skey_val: Buffer.from(creds.signedPreKey.keyPair.public).toString('base64url'),
        e_skey_sig: Buffer.from(creds.signedPreKey.signature).toString('base64url'),
        fdid: creds.phoneId,
        network_ratio_type: '1',
        expid: creds.deviceId,
        simnum: '1',
        hasinrc: '1',
        pid: Math.floor(Math.random() * 1000).toString(),
        id: Buffer.from(creds?.identityId || c201).toString('hex'),
        backup_token: Buffer.from(creds?.backupToken || c202).toString('hex'),
        token: crypto.createHash('md5')
            .update(Buffer.concat([MOBILE_TOKEN, Buffer.from(national)]))
            .digest('hex'),
        mcc: '510',
        mnc: '001',
        sim_mcc: '000',
        sim_mnc: '000',
        reason: '',
        hasav: '1',
    };
}

async function cekBan(phone) {
    const hmacToken = genToken(phone);
    const params = buildParams(phone);
    params.to = hmacToken;
    const qs = Object.entries(params).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
    const url = `${PROXY}/s/s?_=/v2/exist&${qs}`;

    const res = await axios.get(url, {
        validateStatus: () => true,
        headers: {
            'User-Agent': 'WhatsApp/999. Android/9 Device/Google_Phone-G576D',
            'WaMsysRequest': '1',
            'request_token': crypto.randomUUID(),
            'X-Forwarded-Host': 'v.whatsapp.net',
            'Host': 'y9yrsygcg6.execute-api.us-east-1.amazonaws.com',
        },
    });

    const data = res.data;
    if (data.reason === 'blocked') return { banned: true, violation: data.violation_type, detail: data };
    if (data.reason === 'incorrect') return { banned: false, detail: data };
    if (data.reason === 'missing_param') return { banned: null, error: `missing_param: ${data.param}`, detail: data };
    return { banned: null, error: data.reason || 'unknown', detail: data };
}

function checkApiKey(req, res, next) {
    const apiKey = req.headers['api-key'];
    if (!apiKey || !API_KEYS.includes(apiKey)) {
        return res.status(403).json({ error: 'invalid_api_key' });
    }
    next();
}

app.get('/cek', checkApiKey, async (req, res) => {
    const number = req.query.number;
    if (!number) return res.status(400).json({ error: 'missing_number' });
    
    try {
        const result = await cekBan(number.replace(/[^0-9]/g, ''));
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
        console.log(err)
    }
});

app.post('/cek', checkApiKey, async (req, res) => {
    const { number } = req.body;
    if (!number) return res.status(400).json({ error: 'missing_number' });

    try {
        const result = await cekBan(number.replace(/[^0-9]/g, ''));
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
        console.log(err)
    }
});

app.post('/bulk', checkApiKey, async (req, res) => {
    const { numbers } = req.body;
    if (!Array.isArray(numbers)) return res.status(400).json({ error: 'numbers must be array' });

    const results = [];
    for (const num of numbers) {
        const result = await cekBan(num.replace(/[^0-9]/g, ''));
        results.push({ number: num, ...result });
        await new Promise(r => setTimeout(r, 500));
    }
    res.json({ results });
});

app.listen(PORT, () => {
    console.log("Server has been started in http://localhost:" + PORT);
});

export default app;
