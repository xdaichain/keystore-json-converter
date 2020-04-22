const fs = require('fs');
const keythereum = require('keythereum');
const readline = require('readline');
const Writable = require('stream').Writable;

const TARGET_KDF = process.env.TARGET_KDF || 'pbkdf2';
const TARGET_ROUNDS = parseInt(process.env.TARGET_ROUNDS, 10) || 10240;

main();

async function main() {
  console.log();
  console.log('For the safety of your key, please check your Internet connection first. It must be OFF.');
  console.log('Do not use this tool being online.');
  console.log();
  console.log('If you are offline, press ENTER to continue.');
  console.log('If you are still online, please exit with CTRL+C, or disconnect and then press ENTER.');
  console.log();

  await readLine();

  const oldKeystoreFilename = process.env.SOURCE || 'key.json';
  const oldKeystore = require(`${__dirname}/${oldKeystoreFilename}`);

  if (oldKeystore.version != 3) {
    throw 'Only keystore v3 format supported';
  }

  const dklen = oldKeystore.crypto.kdfparams.dklen;
  const salt = Buffer.from(oldKeystore.crypto.kdfparams.salt, 'hex');
  const iv = Buffer.from(oldKeystore.crypto.cipherparams.iv, 'hex');

  let kdfparams;
  if (TARGET_KDF == 'pbkdf2') {
    kdfparams = {
      dklen,
      c: TARGET_ROUNDS,
      prf: 'hmac-sha256'
    };
  } else if (TARGET_KDF == 'scrypt') {
    if (!Number.isInteger(Math.log2(TARGET_ROUNDS)) || TARGET_ROUNDS < 2) {
      throw `Wrong number of iterations for scrypt. Must be 2**m, m > 0`;
    }
    kdfparams = {
      dklen,
      n: TARGET_ROUNDS,
      p: 1,
      r: 8
    };
  } else {
    throw 'Unsupported KDF method';
  }

  const passwordFilename = process.env.PWD_FILENAME || 'node.pwd';
  const password = fs.readFileSync(`${__dirname}/${passwordFilename}`, 'utf8').trim();

  console.log(`Recovering private key from ${oldKeystoreFilename}...`);
  const privateKey = keythereum.recover(password, oldKeystore);

  console.log('Creating a new keystore json...');
  const newKeystore = keythereum.dump(
    password,
    privateKey,
    salt,
    iv, {
      kdf: TARGET_KDF,
      cipher: 'aes-128-ctr',
      kdfparams
    }
  );

  const newKeystoreFilename = process.env.TARGET || `validator.key.0x${newKeystore.address}`;

  const newKeystoreFilepath = `${__dirname}/${newKeystoreFilename}`;
  fs.writeFileSync(newKeystoreFilepath, JSON.stringify(newKeystore), 'utf8');
  
  console.log(`Success! Your new keystore saved to ${newKeystoreFilepath}`);
}

async function readLine() {
  return new Promise((resolve, reject) => {
    var mutableStdout = new Writable({
      write: function(chunk, encoding, callback) {
        if (!this.muted) {
          process.stdout.write(chunk, encoding);
        }
        callback();
      }
    });
    
    mutableStdout.muted = false;
    
    const readlineInterface = readline.createInterface({
      input: process.stdin,
      output: mutableStdout,
      terminal: true
    });

    readlineInterface.question('', () => {
      readlineInterface.close();
      console.log('');
      resolve();
    });
    
    mutableStdout.muted = true;
  });
}

// env SOURCE=key.json TARGET=newKey.json TARGET_KDF=pbkdf2 TARGET_ROUNDS=10240 PWD_FILENAME=node.pwd npm start
