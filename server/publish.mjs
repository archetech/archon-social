import Keymaster from '@didcid/keymaster';
import GatekeeperClient from '@didcid/gatekeeper/client';
import WalletJson from '@didcid/keymaster/wallet/json';
import CipherNode from '@didcid/cipher/node';

const ARCHON_SOCIAL_URL = 'https://archon.social';
const GATEKEEPER_URL = process.env.ARCHON_GATEKEEPER_URL || 'http://flaxlap:4224';
const WALLET_PASSPHRASE = process.env.ARCHON_PASSPHRASE;

if (!WALLET_PASSPHRASE) {
    console.error('Set ARCHON_PASSPHRASE environment variable');
    process.exit(1);
}

async function main() {
    // Initialize keymaster
    const gatekeeper = new GatekeeperClient();
    await gatekeeper.connect({
        url: GATEKEEPER_URL,
        waitUntilReady: true,
        intervalSeconds: 5,
        chatty: true,
    });
    
    const wallet = new WalletJson();
    const cipher = new CipherNode();
    const keymaster = new Keymaster({
        gatekeeper,
        wallet,
        cipher,
        passphrase: WALLET_PASSPHRASE,
    });

    // Set identity to genitrix
    await keymaster.setCurrentId('genitrix');
    console.log('Using identity: genitrix');

    // Get challenge from archon.social
    console.log('Getting challenge...');
    const challengeRes = await fetch(`${ARCHON_SOCIAL_URL}/api/challenge`, {
        credentials: 'include'
    });
    const { challenge } = await challengeRes.json();
    console.log('Challenge:', challenge);

    // Create response
    console.log('Creating response...');
    const response = await keymaster.createResponse(challenge);
    console.log('Response:', response);

    // Login
    console.log('Logging in...');
    const cookies = challengeRes.headers.get('set-cookie');
    const loginRes = await fetch(`${ARCHON_SOCIAL_URL}/api/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Cookie': cookies
        },
        body: JSON.stringify({ response })
    });
    const loginData = await loginRes.json();
    console.log('Login result:', loginData);

    if (!loginData.authenticated) {
        console.error('Failed to authenticate');
        process.exit(1);
    }

    // Get session cookie from login response
    const sessionCookie = loginRes.headers.get('set-cookie') || cookies;

    // Publish
    console.log('Publishing to IPNS...');
    const publishRes = await fetch(`${ARCHON_SOCIAL_URL}/api/admin/publish`, {
        method: 'POST',
        headers: {
            'Cookie': sessionCookie
        }
    });
    const publishData = await publishRes.json();
    console.log('Publish result:', JSON.stringify(publishData, null, 2));
}

main().catch(console.error);
