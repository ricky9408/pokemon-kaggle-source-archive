# Pokémon Kaggle source archive

Source-only archival snapshot of two personal Pokémon TCG AI Battle research projects, retained for code reference during local disk cleanup.

- `pokemoncard_kaggle/`: agent implementations, evaluation libraries, native helpers, tools and source tests. The snapshot includes uncommitted source changes present at archival time.
- `pokemon_kaggle_claude/`: agent implementations, experimental source variants and tools.
- `SOURCE_MANIFEST.json`: SHA-256 and size of each retained source/configuration file.

## Deliberately omitted

Original Git histories, downloaded competition data, card catalogs, replay/scouting data, leaderboard snapshots, evaluation outputs, learned model weights, logs, databases, result reports, local environments/caches, submission archives and engine binaries are not included. Third-party `cg` engine wrappers, vendor/reference source, source-containing engine patch helpers and their related tests, sample submissions and downloaded baselines are also omitted. The bundled third-party engine was competition-use-only and is not redistributed. No ROMs or game assets are included.

The original private repository, if any, has not had its visibility changed. This is a new, history-free archive rather than a complete backup of either project.

## Limitations

This is not a runnable release. Some tools and tests require intentionally omitted data, model files, engine wrappers or native libraries, which must be obtained separately under their respective terms. Source syntax was checked, but the historical experiments and full test suite were not rerun. One local absolute working-directory path was made portable; other source files were preserved as copied.

This archive does not authorize a Kaggle submission or reopen any historical evaluation gate. No license for omitted third-party material is granted, and Pokémon trademarks belong to their respective owners.
