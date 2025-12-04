import 'dotenv/config';
import { DavinciSDK, CensusOrigin, CspCensus } from '@vocdoni/davinci-sdk';
import { Wallet, JsonRpcProvider } from 'ethers';

// Load private key from env (guarded)
const PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY as string | undefined;
if (!PRIVATE_KEY) {
  throw new Error('Missing WALLET_PRIVATE_KEY in environment (.env)');
}

// Create wallet with provider
const provider = new JsonRpcProvider('https://1rpc.io/sepolia');
const wallet = new Wallet(PRIVATE_KEY, provider);

// Initialize SDK
const sdk = new DavinciSDK({
  signer: wallet,
  sequencerUrl: 'https://sequencer-dev.davinci.vote',
  censusUrl: 'https://c3-dev.davinci.vote',
});

await sdk.init();

// Create process (note variable renamed to avoid shadowing global `process`)
const createdProcess = await sdk.createProcess({
  title: 'FINE election',
  description: 'Vote on our next community initiative',

  census: new CspCensus(
    '0x24db33010fad82a4d02be415a713e5897b70994de709430547402fabb56c6b1e', // Root hash (public key)
    'https://informed-guppy-adapting.ngrok-free.app:443', // CSP URL
    10 // Expected number of voters
  ),

  timing: {
    startDate: new Date(Date.now() + 60000),
    duration: 3600 * 3
  },

  ballot: {
    numFields: 1,
    maxValue: '2',
    minValue: '0',
    maxValueSum: '2',
    minValueSum: '0',
    uniqueValues: false,
    costFromWeight: false,
    costExponent: 0
  },

  questions: [
    {
      title: 'Which initiative should we prioritize?',
      choices: [
        { title: 'Community Garden', value: 0 },
        { title: 'Tech Workshop', value: 1 },
        { title: 'Art Exhibition', value: 2 }
      ]
    }
  ]
});

console.log('Process created:', createdProcess.processId);
