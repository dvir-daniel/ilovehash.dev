// Hash algorithm metadata - safe for client components
// This file contains only static data and pure functions

// UI mode types for different algorithm requirements
export type AlgorithmUIMode = 'standard' | 'password' | 'similarity' | 'hmac' | 'hkdf';

// Parameter configuration for algorithm-specific inputs
export interface ParameterConfig {
  id: string;
  label: string;
  type: 'text' | 'number' | 'textarea';
  required: boolean;
  defaultValue?: string | number;
  placeholder?: string;
  min?: number;
  max?: number;
  generateRandom?: boolean; // For salt generation
}

// Type for hash algorithm configuration
export interface HashAlgorithm {
  name: string;
  description: string;
  category: string;
  nodeCryptoName?: string; // For Node.js built-in algorithms
  npmPackage?: string; // For external packages
  outputLength?: number; // Expected output length in bytes
  isSlow?: boolean; // For algorithms that should warn about performance
  legacy?: boolean; // For deprecated algorithms that should be avoided
  demo?: boolean; // Demo/simplified implementation (not cryptographically accurate)
  // UI configuration fields
  uiMode?: AlgorithmUIMode; // Defaults to 'standard' if not specified
  parameters?: ParameterConfig[]; // Algorithm-specific parameters
  supportsComparison?: boolean; // For similarity algorithms
}

// Hash tool interfaces
export interface HashTool {
  id: string;
  name: string;
  description: string;
  category: string;
  algorithm: string;
}

export type HashToolResource = HashTool & {
  url: string;
  date: string;
};

// Category interfaces
export type HashCategoryContext = "use" | "algo";

export interface HashCategoryDetails {
  description: string;
  features: string;
  context: HashCategoryContext;
}

// Comprehensive list of hash algorithms (static definitions).
const RAW_HASH_ALGORITHMS: Record<string, Omit<HashAlgorithm, "demo">> = {
  // Node.js built-in cryptographic hashes
  md5: {
    name: "MD5",
    description: "Legacy MD5 hash - deprecated for security, use SHA-256 or BLAKE2 instead for any security needs",
    category: "Cryptographic",
    nodeCryptoName: "md5",
    outputLength: 16,
    legacy: true,
  },
  sha1: {
    name: "SHA-1",
    description: "Deprecated SHA-1 hash - cryptographically broken, use SHA-256 or SHA-3 for secure applications",
    category: "Cryptographic",
    nodeCryptoName: "sha1",
    outputLength: 20,
    legacy: true,
  },
  sha224: {
    name: "SHA-224",
    description: "Secure SHA-224 cryptographic hash for digital signatures and certificates",
    category: "SHA-2",
    nodeCryptoName: "sha224",
    outputLength: 28,
  },
  sha256: {
    name: "SHA-256",
    description: "Industry-standard SHA-256 secure hash for blockchain, TLS, and digital security",
    category: "SHA-2",
    nodeCryptoName: "sha256",
    outputLength: 32,
  },
  sha384: {
    name: "SHA-384",
    description: "High-security SHA-384 hash for government and enterprise cryptographic applications",
    category: "SHA-2",
    nodeCryptoName: "sha384",
    outputLength: 48,
  },
  sha512: {
    name: "SHA-512",
    description: "Powerful SHA-512 cryptographic hash for maximum security and large data integrity",
    category: "SHA-2",
    nodeCryptoName: "sha512",
    outputLength: 64,
  },
  "sha512-224": {
    name: "SHA-512/224",
    description: "Truncated SHA-512/224 hash - secure 224-bit output from SHA-512 algorithm",
    category: "SHA-2",
    nodeCryptoName: "sha512-224",
    outputLength: 28,
  },
  "sha512-256": {
    name: "SHA-512/256",
    description: "Truncated SHA-512/256 hash - secure 256-bit output from SHA-512 algorithm",
    category: "SHA-2",
    nodeCryptoName: "sha512-256",
    outputLength: 32,
  },
  ripemd160: {
    name: "RIPEMD-160",
    description: "European RIPEMD-160 cryptographic hash - alternative to SHA-1 for digital signatures",
    category: "Cryptographic",
    nodeCryptoName: "ripemd160",
    outputLength: 20,
  },

  // SHA-3 family
  "sha3-224": {
    name: "SHA-3-224",
    description: "Next-generation SHA-3-224 cryptographic hash with quantum-resistant security",
    category: "SHA-3",
    nodeCryptoName: "sha3-224",
    outputLength: 28,
  },
  "sha3-256": {
    name: "SHA-3-256",
    description: "Future-proof SHA-3-256 hash algorithm replacing SHA-2 for enhanced security",
    category: "SHA-3",
    nodeCryptoName: "sha3-256",
    outputLength: 32,
  },
  "sha3-384": {
    name: "SHA-3-384",
    description: "High-security SHA-3-384 hash for government and critical infrastructure protection",
    category: "SHA-3",
    nodeCryptoName: "sha3-384",
    outputLength: 48,
  },
  "sha3-512": {
    name: "SHA-3-512",
    description: "Maximum-security SHA-3-512 hash for large data integrity and digital signatures",
    category: "SHA-3",
    nodeCryptoName: "sha3-512",
    outputLength: 64,
  },

  // Keccak family (underlying sponge construction for SHA-3)
  "keccak-224": {
    name: "Keccak-224",
    description: "Original Keccak-224 hash - foundation of SHA-3 standard for Ethereum and blockchain",
    category: "Cryptographic",
    outputLength: 28,
  },
  "keccak-256": {
    name: "Keccak-256",
    description: "Keccak-256 hash algorithm used in Ethereum blockchain and cryptocurrency security",
    category: "Cryptographic",
    outputLength: 32,
  },
  "keccak-384": {
    name: "Keccak-384",
    description: "High-security Keccak-384 cryptographic hash for advanced digital security applications",
    category: "Cryptographic",
    outputLength: 48,
  },
  "keccak-512": {
    name: "Keccak-512",
    description: "Maximum-security Keccak-512 hash for large-scale data integrity and encryption",
    category: "Cryptographic",
    outputLength: 64,
  },

  // Extendable output functions
  shake128: {
    name: "SHAKE128",
    description: "Flexible SHAKE128 extendable-output function - generate hashes of any length securely",
    category: "SHAKE",
    nodeCryptoName: "shake128",
    outputLength: 32,
    parameters: [
      { id: 'outputLength', label: 'Output Length (bits)', type: 'number', required: false, defaultValue: 256, min: 8, max: 8192, placeholder: 'Output length in bits' }
    ]
  },
  shake256: {
    name: "SHAKE256",
    description: "High-security SHAKE256 extendable-output function for customizable hash lengths",
    category: "SHAKE",
    nodeCryptoName: "shake256",
    outputLength: 32,
    parameters: [
      { id: 'outputLength', label: 'Output Length (bits)', type: 'number', required: false, defaultValue: 256, min: 8, max: 8192, placeholder: 'Output length in bits' }
    ]
  },

  // BLAKE2 family
  blake2b512: {
    name: "BLAKE2b-512",
    description: "Ultra-fast BLAKE2b-512 cryptographic hash with optional keying and personalization",
    category: "BLAKE2",
    nodeCryptoName: "blake2b512",
    outputLength: 64,
    parameters: [
      { id: 'key', label: 'Key (optional)', type: 'text', required: false, placeholder: 'Enter key for keyed hashing' },
      { id: 'salt', label: 'Salt (optional)', type: 'text', required: false, generateRandom: true, placeholder: 'Enter salt' },
      { id: 'personalization', label: 'Personalization (optional)', type: 'text', required: false, placeholder: 'Enter personalization string' },
      { id: 'outputLength', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 64, min: 1, max: 64 }
    ]
  },
  blake2s256: {
    name: "BLAKE2s-256",
    description: "Optimized BLAKE2s-256 hash for 32-bit platforms with excellent performance and security",
    category: "BLAKE2",
    nodeCryptoName: "blake2s256",
    outputLength: 32,
    parameters: [
      { id: 'key', label: 'Key (optional)', type: 'text', required: false, placeholder: 'Enter key for keyed hashing' },
      { id: 'salt', label: 'Salt (optional)', type: 'text', required: false, generateRandom: true, placeholder: 'Enter salt' },
      { id: 'personalization', label: 'Personalization (optional)', type: 'text', required: false, placeholder: 'Enter personalization string' },
      { id: 'outputLength', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 32 }
    ]
  },

  // BLAKE1 family (legacy, use BLAKE2 or BLAKE3 instead)
  "blake1-224": {
    name: "BLAKE-224",
    description: "Legacy BLAKE-224 hash - predecessor to BLAKE2, use BLAKE2b or BLAKE3 for new applications",
    category: "Cryptographic",
    outputLength: 28,
    legacy: true,
  },
  "blake1-256": {
    name: "BLAKE-256",
    description: "Legacy BLAKE-256 hash - original SHA-3 finalist, prefer BLAKE2s or BLAKE3 for modern use",
    category: "Cryptographic",
    outputLength: 32,
    legacy: true,
  },
  "blake1-384": {
    name: "BLAKE-384",
    description: "Legacy BLAKE-384 hash - older standard, upgrade to BLAKE2b or BLAKE3 for better performance",
    category: "Cryptographic",
    outputLength: 48,
    legacy: true,
  },
  "blake1-512": {
    name: "BLAKE-512",
    description: "Legacy BLAKE-512 hash - SHA-3 finalist, replaced by faster BLAKE2b and BLAKE3 algorithms",
    category: "Cryptographic",
    outputLength: 64,
    legacy: true,
  },

  // Non-cryptographic hashes (pure JavaScript implementations)
  murmurhash: {
    name: "MurmurHash",
    description: "Popular MurmurHash algorithm - fast non-cryptographic hash for hash tables and cache keys",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  djb2: {
    name: "DJB2",
    description: "Classic djb2 hash by Daniel Bernstein - simple and fast for basic hash table applications",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  sdbm: {
    name: "SDBM",
    description: "SDBM hash function - reliable non-cryptographic hash for general-purpose data structures",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  "fnv-1": {
    name: "FNV-1",
    description: "Classic FNV-1 hash - simple, fast non-cryptographic hash for general-purpose applications",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  "fnv-1a": {
    name: "FNV-1a",
    description: "Improved FNV-1a hash - better avalanche effect for hash tables and data deduplication",
    category: "Non-cryptographic",
    outputLength: 4,
  },

  // Checksum algorithms (pure JavaScript implementations)
  "crc-32": {
    name: "CRC-32",
    description: "Standard CRC-32 checksum for ZIP files and Ethernet - detects accidental data corruption",
    category: "Checksum",
    outputLength: 4,
  },
  adler32: {
    name: "Adler-32",
    description: "Fast Adler-32 checksum used in zlib compression - optimized for speed over accuracy",
    category: "Checksum",
    outputLength: 4,
  },
  "crc-16": {
    name: "CRC-16",
    description: "Cyclic redundancy check (16-bit)",
    category: "Checksum",
    outputLength: 2,
  },
  "crc-8": {
    name: "CRC-8",
    description: "Cyclic redundancy check (8-bit)",
    category: "Checksum",
    outputLength: 1,
  },
  "crc-64": {
    name: "CRC-64",
    description: "Cyclic redundancy check (64-bit)",
    category: "Checksum",
    outputLength: 8,
  },

  // Modern cryptographic algorithms (external packages)
  blake3: {
    name: "BLAKE3",
    description: "Lightning-fast BLAKE3 cryptographic hash - 3x faster than BLAKE2 with parallel processing",
    category: "Modern",
    npmPackage: "blake3",
    outputLength: 32,
    parameters: [
      { id: 'key', label: 'Key (optional, for keyed hashing)', type: 'text', required: false, placeholder: 'Enter key for keyed BLAKE3' },
      { id: 'outputLength', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 64 }
    ]
  },

  // SHA-3 addon functions (advanced XOF and customization)
  cshake128: {
    name: "cSHAKE128",
    description: "cSHAKE128 customizable XOF - domain-separated SHAKE128 for protocol customization and security",
    category: "Modern",
    outputLength: 32,
    parameters: [
      { id: 'N', label: 'Function Name (N)', type: 'text', required: false, placeholder: 'Function name for domain separation' },
      { id: 'S', label: 'Customization String (S)', type: 'text', required: false, placeholder: 'Customization string' },
      { id: 'dkLen', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 256 }
    ]
  },
  cshake256: {
    name: "cSHAKE256",
    description: "cSHAKE256 customizable XOF - enhanced domain separation for cryptographic protocol design",
    category: "Modern",
    outputLength: 32,
    parameters: [
      { id: 'N', label: 'Function Name (N)', type: 'text', required: false, placeholder: 'Function name for domain separation' },
      { id: 'S', label: 'Customization String (S)', type: 'text', required: false, placeholder: 'Customization string' },
      { id: 'dkLen', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 512 }
    ]
  },
  turboshake128: {
    name: "TurboSHAKE128",
    description: "TurboSHAKE128 with domain separation - optimized XOF for high-performance cryptographic applications",
    category: "Modern",
    outputLength: 32,
    parameters: [
      { id: 'D', label: 'Domain Separation Byte (D)', type: 'number', required: false, defaultValue: 0x1f, min: 0, max: 255, placeholder: 'Domain separation byte (0-255)' },
      { id: 'dkLen', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 256 }
    ]
  },
  turboshake256: {
    name: "TurboSHAKE256",
    description: "TurboSHAKE256 with domain separation - high-security XOF for advanced cryptographic protocols",
    category: "Modern",
    outputLength: 32,
    parameters: [
      { id: 'D', label: 'Domain Separation Byte (D)', type: 'number', required: false, defaultValue: 0x1f, min: 0, max: 255, placeholder: 'Domain separation byte (0-255)' },
      { id: 'dkLen', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 512 }
    ]
  },
  tuplehash256: {
    name: "TupleHash",
    description: "TupleHash for ordered sequences - secure hashing of structured data with tuple preservation",
    category: "Modern",
    outputLength: 32,
    parameters: [
      { id: 'S', label: 'Customization String (S)', type: 'text', required: false, placeholder: 'Customization string' },
      { id: 'dkLen', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 512 }
    ]
  },
  parallelhash256: {
    name: "ParallelHash",
    description: "ParallelHash for large data - high-performance parallel processing of massive datasets",
    category: "Modern",
    outputLength: 32,
    parameters: [
      { id: 'B', label: 'Block Size (B)', type: 'number', required: false, defaultValue: 8192, min: 8, max: 65536, placeholder: 'Block size in bytes' },
      { id: 'S', label: 'Customization String (S)', type: 'text', required: false, placeholder: 'Customization string' },
      { id: 'dkLen', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 512 }
    ]
  },
  kt128: {
    name: "KangarooTwelve (128-bit)",
    description: "KangarooTwelve tree hashing (128-bit output)",
    category: "Modern",
    outputLength: 16,
    parameters: [
      { id: 'dkLen', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 16, min: 1, max: 256 }
    ]
  },
  kt256: {
    name: "KangarooTwelve (256-bit)",
    description: "KangarooTwelve tree hashing (256-bit output)",
    category: "Modern",
    outputLength: 32,
    parameters: [
      { id: 'dkLen', label: 'Output Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 1, max: 512 }
    ]
  },

  // Similarity algorithms
  simhash: {
    name: "SimHash",
    description: "Locality-sensitive SimHash for document similarity - finds near-duplicate content efficiently",
    category: "Similarity",
    outputLength: 8,
    uiMode: 'similarity',
    supportsComparison: true,
  },
  minhash: {
    name: "MinHash",
    description: "MinHash for Jaccard similarity estimation - used in duplicate detection and recommendation systems",
    category: "Similarity",
    outputLength: 8,
    uiMode: 'similarity',
    supportsComparison: true,
  },
  bbitminhash: {
    name: "b-bit MinHash",
    description: "Compact b-bit MinHash - memory-efficient similarity detection for large-scale applications",
    category: "Similarity",
    outputLength: 8,
    uiMode: 'similarity',
    supportsComparison: true,
  },
  superminhash: {
    name: "SuperMinHash",
    description: "Enhanced SuperMinHash (2017) - improved accuracy over traditional MinHash for similarity search",
    category: "Similarity",
    outputLength: 8,
    uiMode: 'similarity',
    supportsComparison: true,
  },
  nilsimsa: {
    name: "Nilsimsa",
    description: "Nilsimsa hash for spam detection - specialized locality-sensitive hash for email and text analysis",
    category: "Similarity",
    outputLength: 32,
    uiMode: 'similarity',
    supportsComparison: true,
  },
  imatch: {
    name: "I-Match",
    description: "I-Match lexicon-based similarity algorithm - customizable duplicate detection using word dictionaries",
    category: "Similarity",
    outputLength: 8,
    uiMode: 'similarity',
    supportsComparison: true,
    parameters: [
      { id: 'lexicon', label: 'Lexicon (comma-separated words)', type: 'textarea', required: true, placeholder: 'Enter lexicon words separated by commas, e.g., word1, word2, word3', defaultValue: 'test, words, for, demo' },
      { id: 'minIntersection', label: 'Minimum Intersection', type: 'number', required: false, defaultValue: 3, min: 0, max: 100 }
    ]
  },


  // Additional non-cryptographic hashes
  "jenkins-one-at-a-time": {
    name: "Jenkins One-at-a-Time",
    description: "Bob Jenkins' One-at-a-Time hash",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  "pearson": {
    name: "Pearson Hash",
    description: "Pearson hashing using lookup table",
    category: "Non-cryptographic",
    outputLength: 1,
  },
  "bernstein": {
    name: "Bernstein Hash",
    description: "Daniel J. Bernstein's hash function",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  "elf-hash": {
    name: "ELF Hash",
    description: "Executable and Linkable Format hash (PJW hash)",
    category: "Non-cryptographic",
    outputLength: 4,
  },

  // More checksum algorithms
  "internet-checksum": {
    name: "Internet Checksum",
    description: "RFC 1071 Internet checksum algorithm",
    category: "Checksum",
    outputLength: 2,
  },
  "fletcher-4": {
    name: "Fletcher-4",
    description: "Compact Fletcher-4 checksum - position-dependent error detection for small data blocks",
    category: "Checksum",
    outputLength: 1,
  },
  "fletcher-8": {
    name: "Fletcher-8",
    description: "Fletcher-8 checksum algorithm - efficient 8-bit error detection with burst error protection",
    category: "Checksum",
    outputLength: 1,
  },
  "fletcher-16": {
    name: "Fletcher-16",
    description: "Standard Fletcher-16 checksum - widely used for network protocols and data integrity",
    category: "Checksum",
    outputLength: 2,
  },
  "fletcher-32": {
    name: "Fletcher-32",
    description: "Enhanced Fletcher-32 checksum - stronger error detection for larger data sets and files",
    category: "Checksum",
    outputLength: 4,
  },

  // Additional algorithms from master list
  // Note: Removed universal-hash as it's not implemented
  "zobrist": {
    name: "Zobrist Hash",
    description: "Zobrist hashing for board games",
    category: "Non-cryptographic",
    outputLength: 8,
  },
  "tabulation": {
    name: "Tabulation Hash",
    description: "Tabulation hashing with high independence",
    category: "Non-cryptographic",
    outputLength: 8,
  },

  argon2i: {
    name: "Argon2i",
    description: "Advanced Argon2i password hashing - protects against side-channel attacks with memory hardness",
    category: "Password",
    npmPackage: "argon2",
    isSlow: true,
    outputLength: 32,
    uiMode: 'password',
    parameters: [
      { id: 'salt', label: 'Salt', type: 'text', required: true, generateRandom: true, placeholder: 'Enter salt or generate random' },
      { id: 'iterations', label: 'Iterations', type: 'number', required: true, defaultValue: 3, min: 1, max: 100 },
      { id: 'memory', label: 'Memory (KB)', type: 'number', required: true, defaultValue: 65536, min: 1024 },
      { id: 'parallelism', label: 'Parallelism', type: 'number', required: true, defaultValue: 4, min: 1, max: 16 },
      { id: 'keyLength', label: 'Key Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 16, max: 64 }
    ]
  },
  argon2d: {
    name: "Argon2d",
    description: "Memory-hard Argon2d password hashing - optimized for resistance to GPU cracking attacks",
    category: "Password",
    npmPackage: "argon2",
    isSlow: true,
    outputLength: 32,
    uiMode: 'password',
    parameters: [
      { id: 'salt', label: 'Salt', type: 'text', required: true, generateRandom: true, placeholder: 'Enter salt or generate random' },
      { id: 'iterations', label: 'Iterations', type: 'number', required: true, defaultValue: 3, min: 1, max: 100 },
      { id: 'memory', label: 'Memory (KB)', type: 'number', required: true, defaultValue: 65536, min: 1024 },
      { id: 'parallelism', label: 'Parallelism', type: 'number', required: true, defaultValue: 4, min: 1, max: 16 },
      { id: 'keyLength', label: 'Key Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 16, max: 64 }
    ]
  },
  argon2id: {
    name: "Argon2id",
    description: "Recommended Argon2id password hashing - hybrid approach for maximum security against all attacks",
    category: "Password",
    npmPackage: "argon2",
    isSlow: true,
    outputLength: 32,
    uiMode: 'password',
    parameters: [
      { id: 'salt', label: 'Salt', type: 'text', required: true, generateRandom: true, placeholder: 'Enter salt or generate random' },
      { id: 'iterations', label: 'Iterations', type: 'number', required: true, defaultValue: 3, min: 1, max: 100 },
      { id: 'memory', label: 'Memory (KB)', type: 'number', required: true, defaultValue: 65536, min: 1024 },
      { id: 'parallelism', label: 'Parallelism', type: 'number', required: true, defaultValue: 4, min: 1, max: 16 },
      { id: 'keyLength', label: 'Key Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 16, max: 64 }
    ]
  },

  has160: {
    name: "HAS-160",
    description: "Hash Algorithm Standard 160-bit",
    category: "Cryptographic",
    outputLength: 20,
    legacy: true,
  },
  gost: {
    name: "GOST",
    description: "Russian GOST R 34.11-2012 cryptographic hash - government standard for Russian Federation",
    category: "Cryptographic",
    npmPackage: "gost-crypto",
    outputLength: 32,
    legacy: true,
  },
  streebog: {
    name: "Streebog",
    description: "Russian Streebog hash function - modern Russian cryptographic standard for digital signatures",
    category: "Cryptographic",
    npmPackage: "streebog",
    outputLength: 32,
    legacy: true,
  },

  // Specialized hash functions
  "luhn": {
    name: "Luhn Algorithm",
    description: "Luhn algorithm - credit card validation checksum used worldwide for financial data integrity",
    category: "Checksum",
    outputLength: 1,
  },
  "verhoeff": {
    name: "Verhoeff Algorithm",
    description: "Verhoeff algorithm - advanced decimal checksum with transposition error detection capabilities",
    category: "Checksum",
    outputLength: 1,
  },
  "damm": {
    name: "Damm Algorithm",
    description: "Damm algorithm - quasigroup-based checksum providing single-digit error correction",
    category: "Checksum",
    outputLength: 1,
  },

  // More non-cryptographic hashes
  "rs-hash": {
    name: "RS Hash",
    description: "Robert Sedgwick's hash function - classic algorithm from 'Algorithms in C' textbook",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  "js-hash": {
    name: "JS Hash",
    description: "Justin Sobel's hash function - simple multiplicative hash for basic applications",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  "bkdr-hash": {
    name: "BKDR Hash",
    description: "BKDR hash by Kernighan and Ritchie - classic string hashing from 'The C Programming Language'",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  "dek-hash": {
    name: "DEK Hash",
    description: "Donald Knuth's hash function - mathematical approach from 'The Art of Computer Programming'",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  "ap-hash": {
    name: "AP Hash",
    description: "Arash Partow's hash function - optimized for speed and distribution in hash tables",
    category: "Non-cryptographic",
    outputLength: 4,
  },
  murmurhash128: {
    name: "MurmurHash128",
    description: "High-performance MurmurHash128 for 128-bit applications - excellent for large hash tables",
    category: "Non-cryptographic",
    outputLength: 16,
  },
  "fnv-1-64": {
    name: "FNV-1 (64-bit)",
    description: "64-bit FNV-1 hash for modern systems - fast and reliable for 64-bit architectures",
    category: "Non-cryptographic",
    outputLength: 8,
  },
  "fnv-1a-64": {
    name: "FNV-1a (64-bit)",
    description: "64-bit FNV-1a hash - optimized avalanche properties for 64-bit computing platforms",
    category: "Non-cryptographic",
    outputLength: 8,
  },

  // xxHash family - extremely popular high-performance hashes
  "xxhash32": {
    name: "xxHash32",
    description: "Ultra-fast xxHash32 for high-performance applications - faster than CRC32 with better distribution",
    category: "Non-cryptographic",
    npmPackage: "xxhash-wasm",
    outputLength: 4,
  },
  "xxhash64": {
    name: "xxHash64",
    description: "Industry-standard xxHash64 for databases and file systems - blazing fast with excellent collision resistance",
    category: "Non-cryptographic",
    npmPackage: "xxhash-wasm",
    outputLength: 8,
  },
  "xxhash128": {
    name: "xxHash128",
    description: "High-performance xxHash128 for large-scale systems - fastest 128-bit hash for big data applications",
    category: "Non-cryptographic",
    npmPackage: "xxhash-wasm",
    outputLength: 16,
  },

  // Additional high-performance hashes
  "cityhash": {
    name: "CityHash",
    description: "Google's CityHash - optimized for modern CPUs with SIMD instructions for maximum speed",
    category: "Non-cryptographic",
    npmPackage: "cityhash",
    outputLength: 8,
  },
  "farmhash": {
    name: "FarmHash",
    description: "Google's FarmHash - successor to CityHash with improved performance across all platforms",
    category: "Non-cryptographic",
    npmPackage: "farmhash",
    outputLength: 8,
  },
  "metrohash": {
    name: "MetroHash",
    description: "MetroHash - extremely fast hash function designed for high-throughput applications",
    category: "Non-cryptographic",
    npmPackage: "metrohash",
    outputLength: 8,
  },
  "t1ha": {
    name: "T1HA",
    description: "Fast Positive Hash (T1HA) - one of the fastest non-cryptographic hashes available",
    category: "Non-cryptographic",
    npmPackage: "t1ha",
    outputLength: 8,
  },

  // High-performance cryptographic hashes
  "highwayhash": {
    name: "HighwayHash",
    description: "Google's HighwayHash - cryptographic hash optimized for speed while maintaining security guarantees",
    category: "Modern",
    npmPackage: "highwayhash",
    outputLength: 8,
  },
  "siphash": {
    name: "SipHash",
    description: "SipHash - cryptographically secure pseudorandom function designed to prevent hash flooding attacks",
    category: "Modern",
    npmPackage: "siphash",
    outputLength: 8,
  },

  // Additional cryptographic primitives
  "poly1305": {
    name: "Poly1305",
    description: "Poly1305 one-time authenticator - fast message authentication used in TLS and cryptography protocols",
    category: "Modern",
    npmPackage: "poly1305-js",
    outputLength: 16,
  },
  "cmac": {
    name: "CMAC",
    description: "Cipher-based Message Authentication Code - standardized MAC using block ciphers like AES",
    category: "Modern",
    npmPackage: "crypto-js", // or specialized package
    outputLength: 16,
  },

  // More password hashing (different from bcrypt)
  scrypt: {
    name: "Scrypt",
    description: "Memory-hard Scrypt password hashing - protects against hardware-based cracking attacks",
    category: "Password",
    npmPackage: "scrypt-js",
    isSlow: true,
    outputLength: 32,
    uiMode: 'password',
    parameters: [
      { id: 'salt', label: 'Salt', type: 'text', required: true, generateRandom: true, placeholder: 'Enter salt or generate random' },
      { id: 'N', label: 'N (CPU/Memory cost)', type: 'number', required: true, defaultValue: 16384, min: 1024 },
      { id: 'r', label: 'r (Block size)', type: 'number', required: true, defaultValue: 8, min: 1, max: 32 },
      { id: 'p', label: 'p (Parallelism)', type: 'number', required: true, defaultValue: 1, min: 1, max: 16 },
      { id: 'dkLen', label: 'Key Length (bytes)', type: 'number', required: false, defaultValue: 64, min: 16, max: 128 }
    ]
  },
  pbkdf2: {
    name: "PBKDF2",
    description: "Standard PBKDF2 password hashing - NIST-approved key derivation for secure password storage",
    category: "Password",
    isSlow: true,
    outputLength: 32,
    uiMode: 'password',
    parameters: [
      { id: 'salt', label: 'Salt', type: 'text', required: true, generateRandom: true, placeholder: 'Enter salt or generate random' },
      { id: 'iterations', label: 'Iterations', type: 'number', required: true, defaultValue: 10000, min: 1000, max: 1000000 },
      { id: 'keyLength', label: 'Key Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 16, max: 64 }
    ]
  },

  // MAC and KDF functions
  hmac: {
    name: "HMAC",
    description: "Cryptographic HMAC for message authentication - protects integrity and authenticity of data",
    category: "Modern",
    outputLength: 32,
    uiMode: 'hmac',
    parameters: [
      { id: 'key', label: 'Key', type: 'text', required: true, placeholder: 'Enter HMAC key' }
    ]
  },
  hkdf: {
    name: "HKDF",
    description: "Secure HKDF key derivation - extracts strong keys from weak input material using HMAC",
    category: "Modern",
    outputLength: 32,
    uiMode: 'hkdf',
    parameters: [
      { id: 'ikm', label: 'Input Key Material (IKM)', type: 'text', required: true, placeholder: 'Enter IKM' },
      { id: 'salt', label: 'Salt', type: 'text', required: true, generateRandom: true },
      { id: 'info', label: 'Info', type: 'text', required: false, placeholder: 'Context/application info' },
      { id: 'keyLength', label: 'Key Length (bytes)', type: 'number', required: false, defaultValue: 32, min: 16, max: 64 }
    ]
  },

  // Competition cryptographic hashes (moved to Modern)
  cubehash: {
    name: "CubeHash",
    description: "CubeHash cryptographic hash - SHA-3 finalist known for simple design and security margins",
    category: "Modern",
    outputLength: 32,
  },
  echo: {
    name: "ECHO",
    description: "ECHO cryptographic hash - wide-pipe design for enhanced security against length extension attacks",
    category: "Modern",
    outputLength: 32,
  },
  skein: {
    name: "Skein",
    description: "Skein cryptographic hash - highly optimized for 64-bit platforms with tweakable parameters",
    category: "Modern",
    outputLength: 32,
  },
  "blue-midnight-wish": {
    name: "Blue Midnight Wish",
    description: "Blue Midnight Wish hash - SHA-3 finalist with unique double-pipe construction for security",
    category: "Modern",
    outputLength: 32,
  },
  grøstl: {
    name: "Grøstl",
    description: "Grøstl cryptographic hash - AES-based design providing provable security and high performance",
    category: "Modern",
    outputLength: 32,
  },


  // Deprecated cryptographic algorithms (pure JavaScript implementations)
  md2: {
    name: "MD2",
    description: "Obsolete MD2 hash - cryptographically broken, avoid for any security-critical applications",
    category: "Cryptographic",
    outputLength: 16,
    legacy: true,
  },
  md4: {
    name: "MD4",
    description: "Deprecated MD4 hash - vulnerable to collision attacks, use SHA-256 or stronger alternatives",
    category: "Cryptographic",
    outputLength: 16,
    legacy: true,
  },
};

export const HASH_ALGORITHMS: Record<string, HashAlgorithm> = Object.fromEntries(
  Object.entries(RAW_HASH_ALGORITHMS).map(([id, cfg]) => [
    id,
    {
      ...cfg,
      demo: !("nodeCryptoName" in cfg),
    },
  ]),
);

// Get algorithms by category (client-safe function)
export function getAlgorithmsByCategory(): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  Object.keys(HASH_ALGORITHMS).forEach(algo => {
    const category = HASH_ALGORITHMS[algo].category;
    if (!result[category]) result[category] = [];
    result[category].push(algo);
  });
  return result;
}

// Category details
/**
 * Single source of truth for category copy + grouping.
 * (Moved from `src/app/categories/page.tsx`.)
 */
export const HASH_CATEGORY_DETAILS: Record<string, HashCategoryDetails> = {
  // Use-based categories (what you use them for)
  Cryptographic: {
    description:
      "Secure hash functions for cryptographic applications including digital signatures, certificates, blockchain, and secure communications.",
    features: "High security, collision resistance, preimage resistance",
    context: "use",
  },
  Password: {
    description:
      "Specialized hash functions designed for password hashing with features like salt support and intentionally slow computation.",
    features: "Password security, salt support, computational hardness",
    context: "use",
  },
  Checksum: {
    description:
      "Error-detection algorithms for verifying data integrity. Includes CRC variants, Fletcher checksums, and other validation methods.",
    features: "Error detection, fast, various bit lengths",
    context: "use",
  },
  Similarity: {
    description:
      "Locality-sensitive hash functions used for similarity detection, duplicate finding, and nearest neighbor searches.",
    features: "Similarity detection, probabilistic, specialized use cases",
    context: "use",
  },
  "Non-cryptographic": {
    description:
      "Fast hash functions designed for non-cryptographic purposes like hash tables, checksums, and data integrity verification.",
    features: "High speed, good distribution, non-cryptographic",
    context: "use",
  },

  // Algorithm family categories (specific algorithm families)
  "SHA-2": {
    description:
      "Modern cryptographic hash functions recommended for security applications. Includes SHA-256, SHA-384, and SHA-512 with truncated variants.",
    features: "High security, standardized, widely adopted",
    context: "algo",
  },
  "SHA-3": {
    description:
      "Next-generation cryptographic hash functions based on the Keccak algorithm. Offers better security margins and flexible output sizes.",
    features: "Future-proof, quantum-resistant design, extendable output",
    context: "algo",
  },
  SHAKE: {
    description:
      "Extendable-output functions (XOF) from the SHA-3 family. Can produce hash outputs of any desired length.",
    features: "Variable output length, SHA-3 based, flexible",
    context: "algo",
  },
  BLAKE2: {
    description:
      "High-performance cryptographic hash functions optimized for speed while maintaining security. Excellent for performance-critical applications.",
    features: "Fast, secure, customizable output size",
    context: "algo",
  },
  Modern: {
    description:
      "Next-generation hash functions with improved security and performance characteristics compared to older standards.",
    features: "Latest technology, enhanced security, optimized",
    context: "algo",
  },
};

// Category utility functions
export function getHashCategoryDetails(title: string): HashCategoryDetails {
  return (
    HASH_CATEGORY_DETAILS[title] || {
      description: `${title} hash algorithms for various computing applications.`,
      features: "Specialized hashing functionality",
      context: "algo",
    }
  );
}

const ALL_CATEGORY_TITLES = Object.keys(getAlgorithmsByCategory());

export function hashCategoryNameToSlug(categoryName: string): string {
  // Simple slug conversion (can be enhanced if needed)
  return categoryName
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "") // keep spaces + hyphens
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .trim();
}

export function hashCategorySlugToName(slug: string): string {
  // Create a reverse map for slug to category conversion
  const slugToCategoryMap: Record<string, string> = {};
  ALL_CATEGORY_TITLES.forEach(category => {
    slugToCategoryMap[hashCategoryNameToSlug(category)] = category;
  });
  return slugToCategoryMap[slug] || slug;
}

export function getAllHashCategoryTitles(): string[] {
  return [...ALL_CATEGORY_TITLES];
}

// Hash tools generation
const TODAY = "2026-01-19";

// Generate tools from implemented algorithms
export const HASH_TOOLS: HashToolResource[] = Object.keys(HASH_ALGORITHMS).map(
  (algo) => {
    const config = HASH_ALGORITHMS[algo];
    const categorySlug = hashCategoryNameToSlug(config.category);

    return {
      id: algo,
      name: config.name,
      description: config.description,
      category: config.category,
      algorithm: algo,
      url: `/hashes/${categorySlug}/${algo}`,
      date: TODAY,
    };
  },
);