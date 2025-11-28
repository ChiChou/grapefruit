fetch(
  "https://raw.githubusercontent.com/apple-oss-distributions/Security/refs/heads/main/OSX/sec/Security/SecItemConstants.c",
)
  .then((r) => r.text())
  .then((t) => {
    console.log(
      JSON.stringify(
        [...t.matchAll(/SEC_CONST_DECL\s+\((\w+),/g)].map((m) => m[1]),
      ),
    );
  });
