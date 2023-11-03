with import <nixpkgs> {};

mkShell {
  name = "mirrorcheck-shell";
  buildInputs = [
    (python3.withPackages (pypkgs: with pypkgs; [
      requests jinja2 validators
    ]))
  ];
}
