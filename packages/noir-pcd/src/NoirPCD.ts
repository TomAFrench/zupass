import {
  BarretenbergApiAsync,
  Crs,
  RawBuffer,
  newBarretenbergApiAsync
} from "@aztec/bb.js/dest/node/index.js";
import { Ptr } from "@aztec/bb.js/dest/node/types";
import {
  ArgumentTypeName,
  DisplayOptions,
  PCD,
  PCDArgument,
  PCDPackage,
  SerializedPCD,
  StringArgument
} from "@pcd/pcd-types";
import {
  SemaphoreIdentityPCD,
  SemaphoreIdentityPCDTypeName
} from "@pcd/semaphore-identity-pcd";
import {
  SemaphoreSignaturePCD,
  SemaphoreSignaturePCDPackage
} from "@pcd/semaphore-signature-pcd";
import { readFileSync } from "fs";
import JSONBig from "json-bigint";
import { v4 as uuid } from "uuid";
import { gunzipSync } from "zlib";
import { NoirCardBody } from "./CardBody";

export const NoirPCDTypeName = "noir-pcd";

export interface NoirPCDInitArgs {
  circuitPath: string;
  proverWitnessPath: string;
}

export interface NoirPCDArgs {
  identity: PCDArgument<SemaphoreIdentityPCD>;
  circuitPath: StringArgument;
  proverWitnessPath: StringArgument;
}

export interface NoirPCDClaim {
  proof: string;
}

export interface NoirPCDProof {
  signatureProof: SerializedPCD<SemaphoreSignaturePCD>;
  noirProof: Uint8Array;
}

export class NoirPCD implements PCD<NoirPCDClaim, NoirPCDProof> {
  type = NoirPCDTypeName;
  claim: NoirPCDClaim;
  proof: NoirPCDProof;
  id: string;

  public constructor(
    id: string,
    claim: NoirPCDClaim,
    proof: NoirPCDProof
  ) {
    this.id = id;
    this.claim = claim;
    this.proof = proof;
  }
}

interface CircuitParams {
  api: BarretenbergApiAsync;
  acirComposer: Ptr;
  circuitSize: number;
}
let initParams: CircuitParams | undefined = undefined;
export async function init(args: NoirPCDInitArgs): Promise<void> {
  const circuitDecompressed = getBytecode(args.circuitPath);
  const api = await newBarretenbergApiAsync();

  const [total] = await api.acirGetCircuitSizes(circuitDecompressed);
  const subgroupSize = Math.pow(2, Math.ceil(Math.log2(total)));
  const crs = await Crs.new(subgroupSize + 1);
  await api.commonInitSlabAllocator(subgroupSize);
  await api.srsInitSrs(
    new RawBuffer(crs.getG1Data()),
    crs.numPoints,
    new RawBuffer(crs.getG2Data())
  );

  const acirComposer = await api.acirNewAcirComposer(subgroupSize);
  initParams = { api, acirComposer, circuitSize: subgroupSize };
}

function getBytecode(bytecodePath: string) {
  const encodedCircuit = readFileSync(bytecodePath, "utf-8");
  const buffer = Buffer.from(encodedCircuit, "base64");
  const decompressed = gunzipSync(buffer);
  return decompressed;
}

function getWitness(witnessPath: string) {
  const data = readFileSync(witnessPath);
  const decompressed = gunzipSync(data);
  return decompressed;
}

export async function prove(args: NoirPCDArgs): Promise<NoirPCD> {
  if (!initParams) {
    throw new Error(
      "cannot make Noir Circuit proof: init has not been called yet"
    );
  }
  if (args.identity.value === undefined) {
    throw new Error(`missing argument identity`);
  }
  if (args.circuitPath.value === undefined) {
    throw new Error(`missing argument circuitPath`);
  }
  if (args.proverWitnessPath.value === undefined) {
    throw new Error(`missing argument proverWitnessPath`);
  }

  const bytecode = getBytecode(args.circuitPath.value);
  const witness = getWitness(args.proverWitnessPath.value);
  const proof = await initParams.api.acirCreateProof(
    initParams.acirComposer,
    bytecode,
    witness,
    false
  );

  const semaphoreSignature = await SemaphoreSignaturePCDPackage.prove({
    identity: {
      argumentType: ArgumentTypeName.PCD,
      pcdType: SemaphoreIdentityPCDTypeName,
      value: args.identity.value
    },
    signedMessage: {
      argumentType: ArgumentTypeName.String,
      value: proof.toString()
    }
  });

  return new NoirPCD(
    uuid(),
    {
      proof: proof.toString()
    },
    {
      signatureProof: await SemaphoreSignaturePCDPackage.serialize(
        semaphoreSignature
      ),
      noirProof: proof
    }
  );
}

export async function verify(pcd: NoirPCD): Promise<boolean> {
  if (!initParams) {
    throw new Error(
      "cannot verify Noir Circuit proof: init has not been called yet"
    );
  }
  const semaphoreSignature = await SemaphoreSignaturePCDPackage.deserialize(
    pcd.proof.signatureProof.pcd
  );
  const proofValid = await SemaphoreSignaturePCDPackage.verify(
    semaphoreSignature
  );

  // the semaphore signature of the proof must be valid
  if (!proofValid) {
    return false;
  }

  // the string that the semaphore signature signed must equal to the Noir proof
  if (semaphoreSignature.claim.signedMessage !== pcd.proof.toString()) {
    return false;
  }

  const verified = await initParams.api.acirVerifyProof(
    initParams.acirComposer,
    pcd.proof.noirProof,
    false
  );

  return verified;
}

export async function serialize(
  pcd: NoirPCD
): Promise<SerializedPCD<NoirPCD>> {
  return {
    type: NoirPCDTypeName,
    pcd: JSONBig().stringify(pcd)
  } as SerializedPCD<NoirPCD>;
}

export async function deserialize(serialized: string): Promise<NoirPCD> {
  return JSONBig().parse(serialized);
}

export function getDisplayOptions(pcd: NoirPCD): DisplayOptions {
  return {
    header: "Proof: " + pcd.claim.proof,
    displayName: "semaphore-sig-" + pcd.id.substring(0, 4)
  };
}

/**
 * PCD-conforming wrapper to sign messages using one's Semaphore public key. This is a small
 * extension of the existing Semaphore protocol, which is mostly geared at group signatures.
 * Find documentation of Semaphore here: https://semaphore.appliedzkp.org/docs/introduction
 */
export const NoirPCDPackage: PCDPackage<
  NoirPCDClaim,
  NoirPCDProof,
  NoirPCDArgs,
  NoirPCDInitArgs
> = {
  name: NoirPCDTypeName,
  renderCardBody: NoirCardBody,
  getDisplayOptions,
  init,
  prove,
  verify,
  serialize,
  deserialize
};
