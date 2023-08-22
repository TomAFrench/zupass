/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { ArgumentTypeName } from "@pcd/pcd-types";
import {
  SemaphoreIdentityPCDPackage,
  SemaphoreIdentityPCDTypeName
} from "@pcd/semaphore-identity-pcd";
import { Identity } from "@semaphore-protocol/identity";
import assert from "assert";
import * as path from "path";
import "mocha";
import { NoirPCDPackage } from "../src/NoirPCD";

const circuitPath = path.join(
  __dirname,
  "../artifacts/ecdsa_circuit/target/ecdsa_circuit.json"
);
const proverWitnessPath = path.join(
  __dirname,
  "../artifacts/ecdsa_circuit/target/witness.tr"
);
const zkeyFilePath = path.join(__dirname, "../artifacts/16.zkey");
const wasmFilePath = path.join(__dirname, "../artifacts/16.wasm");

describe("Noir PCD", function () {
  beforeAll(async function () {
    await NoirPCDPackage.init?.({
      zkeyFilePath,
      wasmFilePath,
      circuitPath,
      proverWitnessPath
    });
  });

  it("should generate correct proof", async function () {
    const identity = await SemaphoreIdentityPCDPackage.prove({
      identity: new Identity()
    });
    const serializedIdentity = await SemaphoreIdentityPCDPackage.serialize(
      identity
    );

    const ethereumPCD = await NoirPCDPackage.prove({
      circuitPath: {
        argumentType: ArgumentTypeName.String,
        value: circuitPath
      },
      proverWitnessPath: {
        argumentType: ArgumentTypeName.String,
        value: proverWitnessPath
      },
      identity: {
        argumentType: ArgumentTypeName.PCD,
        pcdType: SemaphoreIdentityPCDTypeName,
        value: serializedIdentity
      }
    });

    assert(await NoirPCDPackage.verify(ethereumPCD));
  });
});
