/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { ArgumentTypeName } from "@pcd/pcd-types";
import {
    SemaphoreIdentityPCDPackage,
    SemaphoreIdentityPCDTypeName,
} from "@pcd/semaphore-identity-pcd";
import { Identity } from "@semaphore-protocol/identity";
import assert from "assert";
import "mocha";
import * as path from "path";
import { NoirPCDPackage } from "../src/NoirPCD";

const circuitPath: string = path.join(__dirname, "../artifacts/ecdsa_circuit/target/ecdsa_circuit.json");
const proverWitnessPath: string = path.join(__dirname, "../artifacts/ecdsa_circuit/Prover.toml");

describe("Noir PCD", function () {
  this.timeout(30 * 1000);

  this.beforeAll(async function () {
    await NoirPCDPackage.init!({
        circuitPath,
        proverWitnessPath,
    });
  });

  it("noir proof test", async function () {
    const identity = await SemaphoreIdentityPCDPackage.prove({
      identity: new Identity(),
    });
    const serializedIdentity = await SemaphoreIdentityPCDPackage.serialize(
      identity
    );

    const ethereumPCD = await NoirPCDPackage.prove({
      circuitPath: {
        argumentType: ArgumentTypeName.String,
        value: circuitPath,
      },
      proverWitnessPath: {
        argumentType: ArgumentTypeName.String,
        value: proverWitnessPath,
      },
      identity: {
        argumentType: ArgumentTypeName.PCD,
        pcdType: SemaphoreIdentityPCDTypeName,
        value: serializedIdentity,
      },
    });

    assert(await NoirPCDPackage.verify(ethereumPCD));
  });

});
