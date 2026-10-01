import { describe, expect, it } from "vitest";
import {
  PISHIP_CLIENT_HEADER,
  PISHIP_CLIENT_PROTOCOL,
  pishipClientHeader,
} from "./client.js";

describe("PiShip-Client", () => {
  it("is a structured field dictionary of the distribution, its version, PiShip's version, and the protocol", () => {
    expect(PISHIP_CLIENT_HEADER).toBe("piship-client");
    expect(PISHIP_CLIENT_PROTOCOL).toBe(1);
    expect(
      pishipClientHeader({
        distribution: "acmecode",
        version: "1.4.0-rc.1+build.7",
        piship: "0.7.0",
      }),
    ).toBe(
      'distribution="acmecode", version="1.4.0-rc.1+build.7", piship="0.7.0", protocol=1',
    );
  });

  it("refuses a value a structured field string cannot carry", () => {
    for (const bad of ['a"b', "a\\b", "a\nb", "", "caf\u00e9"])
      expect(() =>
        pishipClientHeader({
          distribution: bad,
          version: "1.0.0",
          piship: "0.7.0",
        }),
      ).toThrow(TypeError);
  });
});
