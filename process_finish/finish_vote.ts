// finish_vote.ts
import 'dotenv/config';
import util from 'node:util';
import { DavinciSDK, TxStatus } from '@vocdoni/davinci-sdk';
import { Wallet, JsonRpcProvider } from 'ethers';

async function main() {
  const PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY;
  const RPC_URL = process.env.RPC_URL ?? 'https://1rpc.io/sepolia';
  const PROCESS_ID = process.env.PROCESS_ID;

  if (!PRIVATE_KEY) throw new Error('Missing WALLET_PRIVATE_KEY in .env');
  if (!PROCESS_ID) throw new Error('Missing PROCESS_ID in .env');

  console.log('Environment loaded:',
    '\n - WALLET_PRIVATE_KEY present?', !!PRIVATE_KEY,
    '\n - RPC_URL:', RPC_URL,
    '\n - PROCESS_ID:', PROCESS_ID
  );

  const signer = new Wallet(PRIVATE_KEY, new JsonRpcProvider(RPC_URL));

  const sdk = new DavinciSDK({
    signer,
    environment: 'dev',
    sequencerUrl: 'https://sequencer-dev.davinci.vote',
    useSequencerAddresses: true,
  });

  await sdk.init();

  console.log('Ending process:', PROCESS_ID);

  const stream = sdk.endProcessStream(PROCESS_ID);

  for await (const event of stream) {
    switch (event.status) {
      case TxStatus.Pending:
        console.log('⏳ Pending. Hash:', (event as any).hash ?? 'unknown');
        break;

      case TxStatus.Completed: {
        const txHash =
          (event as any).response?.transactionHash ??
          (event as any).response?.transaction?.hash ??
          (event as any).hash ??
          'unknown';

        console.log('✅ Completed! TX hash:', txHash);
        if ((event as any).response) {
          console.log('response:', (event as any).response);
        }
        break;
      }

      case TxStatus.Failed:
        console.error('❌ Failed:', (event as any).error ?? event);
        break;

      case TxStatus.Reverted:
        console.error('⚠️ Reverted. Reason:', (event as any).reason ?? event);
        break;

      default:
        console.log('• Unknown event:', event);
    }
  }

  console.log('Stream closed');
}

function prettyError(err: unknown) {
  if (err instanceof Error) {
    console.error('Fatal error:', err.stack ?? err.message);
  } else {
    console.error('Fatal error (non-error):', util.inspect(err, {
      showHidden: true,
      depth: null,
      colors: true,
    }));
  }
}

main().catch(err => {
  prettyError(err);
  process.exit(1);
});
