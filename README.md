# pluriƀit

An experimental, privacy-focused cryptocurrency featuring a novel consensus mechanism. Pluribit is built as a hybrid system with a Rust core compiled to WASM for cryptographic operations and a Node.js layer for networking and orchestration.

## Core Features

  * **Mandatory Privacy:** Implements **MimbleWimble** for confidential transactions. All amounts and addresses are obscured on-chain.
  * **Non-Interactive Transactions:** Utilizes **Stealth Addresses** to allow payments without requiring the sender and receiver to be online simultaneously.
  * **Novel Consensus Mechanism:** A unique three-stage process ($PoW \rightarrow VDF \rightarrow VRF$) designed for fairness and ASIC resistance.
  * **Decentralized P2P Networking:** Built on **libp2p**, using the public DHT for peer discovery without centralized bootstrap servers.
  * **IP Obfuscation:** Implements **Dandelion** for transaction propagation to obscure the originating IP address of a transaction.

-----

## Architecture

Pluriƀit uses a hybrid architecture to balance performance, security, and development velocity.

  * **Rust Core (`pluribit_core`)**: The cryptographic engine of the project, compiled to WebAssembly. It handles all critical consensus logic, state validation, transaction construction, and MimbleWimble primitives.
  * **Node.js Orchestration Layer (`pluribit-node`)**: The main process that runs the node. It manages the libp2p network stack, database interactions (LevelDB), mining coordination via worker threads, and a JSON RPC server for the block explorer.
  * **Web Block Explorer**: A simple web interface for viewing blockchain statistics, blocks, and mempool status, served directly by the Node.js process.

-----

## Consensus Mechanism

pluriƀit's consensus is a multi-stage lottery designed to favor decentralization by neutralizing the raw hardware advantages common in pure Proof-of-Work systems.

#### 1\. Proof-of-Work (Spam Resistance)

  * A trivial PoW puzzle must be solved to begin the block proposal process.
  * This acts as a rate-limiting mechanism to prevent spam, not as the primary security mechanism. It grants a "ticket" to participate in the next stage.

#### 2\. Verifiable Delay Function (VDF)

  * The PoW solution is used as input to a VDF.
  * The VDF requires a fixed duration of sequential computation that cannot be significantly parallelized or sped up with specialized hardware.
  * This enforces a **time cost**, equalizing the playing field between miners with different levels of computational power.

#### 3\. Verifiable Random Function (VRF)

  * The output of the completed VDF is used as the input for a VRF.
  * The VRF produces an unpredictable but verifiable random number.
  * If this number is below the current network target, the miner wins the right to produce the next block.

-----

## Privacy Model

Privacy is mandatory and enforced at the protocol level.

  * **MimbleWimble**: Transactions consist only of inputs, outputs, and kernels. There are no on-chain addresses or transaction amounts. The protocol validates that no coins are created or destroyed without revealing the values being transacted.
  * **Stealth Addresses**: To enable non-interactive transactions, a sender uses the recipient's public scan key to generate a one-time ephemeral public key (`R`) where the funds are sent. A shared secret, known only to the sender and receiver, is used to encrypt the transaction's value and blinding factor. Only the recipient can use their private scan key to discover and spend these funds.
  * **Block-level Cut-through**: To reduce block size and enhance privacy, transactions within the same block are aggregated. Inputs and outputs that are both created and spent within the block are "cut through" and removed from the final block data.
  * **Dandelion Propagation**: Transactions are not immediately broadcast to the entire network. They are first passed secretly along a random path of peers (the "stem" phase) before being broadcast widely (the "fluff" phase), making it difficult to trace a transaction back to its source IP.

-----

## Networking

  * **Peer-to-Peer Stack**: The network is built on **libp2p**, handling peer discovery, stream multiplexing, and connection encryption. Nodes use the public Kad-DHT to find each other, eliminating the need for hardcoded bootstrap nodes.
  * **Message Protocol**: All network messages are strictly defined and serialized using **Protocol Buffers (Protobuf)**. This provides a secure, efficient, and unambiguous binary format for communication, preventing a class of parsing-based vulnerabilities.
  * **Peer Verification**: New peers must solve a simple challenge-response PoW before their messages are accepted, mitigating spam and simple DoS attacks.

-----

## How to Run

### Prerequisites

  * Rust and `cargo`
  * Node.js (v18+) and `npm`
  * `wasm-pack`

### Installation & Build

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/PubliusPseudis/pluribit.git
    cd pluribit
    ```

2.  **Install Node.js dependencies:**

    ```bash
    npm install
    ```

3.  **Build the project:**
    This command will build the Protobuf definitions, compile the Rust core to WASM, and prepare the Node.js application.

    ```bash
    npm run build
    ```

### Running the Node

Start the pluriƀit node using the start script:

```bash
npm run start
```

The node will initialize the P2P network and begin syncing with peers. A command-line interface will become available for interacting with the node.

-----

## Project Status

**Disclaimer:** This is an experimental project built to explore novel concepts in cryptocurrency design. It is **not intended for production use** and should not be used to store significant value. The code is provided as-is for educational and research purposes.
