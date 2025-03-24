![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
![NodeJS](https://img.shields.io/badge/node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white)
![Express.js](https://img.shields.io/badge/express.js-%23404d59.svg?style=for-the-badge&logo=express&logoColor=%2361DAFB)
![Jest](https://img.shields.io/badge/-jest-%23C21325?style=for-the-badge&logo=jest&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![ESLint](https://img.shields.io/badge/ESLint-4B3263?style=for-the-badge&logo=eslint&logoColor=white)
![Yarn](https://img.shields.io/badge/yarn-%232C8EBB.svg?style=for-the-badge&logo=yarn&logoColor=white)

# Venn Rugpull Detector

A custom detector for the Venn Network that analyzes smart contracts for potential rugpull vulnerabilities. This detector helps protect users and protocols by identifying suspicious patterns and high-risk behaviors that could indicate a potential rugpull attack.

## Features

The detector analyzes transactions for the following risk patterns:

### 1. Suspicious Function Calls
- **Ownership Transfer** (HIGH Risk) - Detects calls to transfer contract ownership
- **Blacklisting** (HIGH Risk) - Identifies functions that can block user addresses
- **Contract Pause** (MEDIUM Risk) - Detects pause functionality that could freeze user funds
- **Self-Destruct** (HIGH Risk) - Identifies self-destruct capabilities that could permanently lock funds
- **Contract Upgrades** (MEDIUM Risk) - Detects upgrade functions that could change contract behavior

### 2. Token Ownership Concentration
- Monitors token distribution and alerts when a single address holds more than 50% of the total supply
- Helps identify potential manipulation risks from whale addresses

### 3. Suspicious State Changes
- Tracks significant balance changes
- Alerts on large withdrawals (>80% of balance)
- Identifies patterns that could indicate a rugpull in progress

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/venn-rugpull-detector.git
cd venn-rugpull-detector

# Install dependencies
yarn install
```

## Usage

### Development Mode
```bash
yarn dev
```

### Production Mode
```bash
yarn build
yarn start
```

### Docker Deployment
```bash
docker build -f Dockerfile . -t venn-rugpull-detector
docker run -p 3000:3000 venn-rugpull-detector
```

## Example Detection Scenarios

### Scenario 1: Ownership Transfer Attack
```json
{
  "chainId": 1,
  "hash": "0x...",
  "trace": {
    "calls": [
      {
        "input": "0xf2fde38b...", // transferOwnership function signature
        "from": "0x123...",
        "to": "0x456..."
      }
    ]
  }
}
```
**Result**: HIGH risk - Ownership transfer detected

### Scenario 2: Token Concentration Risk
```json
{
  "chainId": 1,
  "hash": "0x...",
  "trace": {
    "pre": {
      "0x123...": { "balance": "600000000000000000000" },
      "0x456...": { "balance": "400000000000000000000" }
    }
  }
}
```
**Result**: HIGH risk - Single address holds 60% of tokens

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Security

This detector is part of the Venn Network's security infrastructure. While it helps identify potential rugpull risks, it should not be the only security measure in place. Always conduct thorough security audits and implement multiple layers of protection.

For real-world examples of transactions that would trigger this detector, please check the test suite.

## Table of Contents
- [Introduction](#venn-custom-detector-boilerplate)
- [Quick Start](#quick-start)
- [What's inside?](#-whats-inside)
- [Local development:](#️-local-development)
- [Deploy to production](#-deploy-to-production)

## ✨ Quick start
1. Clone or fork this repo and install dependencies using `yarn install` _(or `npm install`)_
2. Find the detection service under: `src/modules/detection-module/service.ts`

    ```ts
    import { DetectionResponse, DetectionRequest } from './dtos'

    /**
     * DetectionService
     *
     * Implements a `detect` method that receives an enriched view of an
     * EVM compatible transaction (i.e. `DetectionRequest`)
     * and returns a `DetectionResponse`
     *
     * API Reference:
     * https://github.com/ironblocks/venn-custom-detection/blob/master/docs/requests-responses.docs.md
     */
    export class DetectionService {
        /**
         * Update this implementation code to insepct the `DetectionRequest`
         * based on your custom business logic
         */
        public static detect(request: DetectionRequest): DetectionResponse {
            
            /**
             * For this "Hello World" style boilerplate
             * we're mocking detection results using
             * some random value
             */
            const detectionResult = Math.random() < 0.5;


            /**
             * Wrap our response in a `DetectionResponse` object
             */
            return new DetectionResponse({
                request,
                detectionInfo: {
                    detected: detectionResult,
                },
            });
        }
    }
    ```

3. Implement your own logic in the `detect` method
4. Run `yarn dev` _(or `npm run dev`)_
5. That's it! Your custom detector service is now ready to inspect transaction

## 📦 What's inside?
This boilerplate is built using `Express.js`, and written in `TypeScript` using `NodeJS`.  
You can use it as-is by adding your own security logic to it, or as a reference point when using a different programming language.

**Notes on the API**
1. Your detector will get a `DetectionRequest`, and is expected to respond with a `DetectionResponse`

See our [API Reference](https://github.com/ironblocks/venn-custom-detection/blob/master/docs/requests-responses.docs.md) for more information.

## 🛠️ Local Development

**Environment Setup**

Create a `.env` file with:

```bash
PORT=3000
HOST=localhost
LOG_LEVEL=debug
```

**Runing In Dev Mode**
```bash
yarn        # or npm install
yarn dev    # or npm run dev
```

## 🚀 Deploy To Production

**Manual Build**

```bash
yarn build      # or npm run build
yarn start      # or npm run start
```


**Using Docker**
```bash
docker build -f Dockerfile . -t my-custom-detector
```

