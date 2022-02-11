// import { base642hex, hex2base64 } from "../Utils";

beforeAll(() => {
    Date.now = jest.fn(() => new Date(Date.UTC(2017, 0, 1)).valueOf());
});

describe("utils", () => {

    // FEB 2022: skipped because jest/node no longer supports btoa and any workarounds to enable it will just
    // end up testing the workaround rather than what will actually happen in a user's browser.
    // test("hex roundtrips through base64", async () => {
    //     // b64 = "9E0mTE3/KZvKCvuMSDOvsFe+BNSH9oz812y3BsZn4/E=";
    //     const hex = "f44d264c4dff299bca0afb8c4833afb057be04d487f68cfcd76cb706c667e3f1";

    //     const temp = hex2base64(hex);
    //     const result = base642hex(temp);
    //     expect(result).toEqual(hex);
    // });

    test("always true", async () => {
        expect(true);
    });
});
