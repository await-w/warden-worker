# D1 incremental migrations

`sql/schema.sql` is the consolidated database baseline as of 2026-07-22. Put
every database change after that baseline in this directory as a sequentially
numbered `.sql` file, for example:

```text
0001_add_example_column.sql
0002_create_example_table.sql
```

Create a migration with:

```bash
wrangler d1 migrations create vaultsql add_example_column
```

Rules:

- Never edit, rename, reorder, or delete a migration after it has been applied.
- Test each migration against a database initialized from `sql/schema.sql` plus
  all earlier migrations.
- Do not copy post-baseline changes back into `sql/schema.sql`; new databases
  receive the baseline first and then every migration in this directory.
- Apply database migrations before deploying Worker code that depends on them.

Wrangler records applied files in D1's `d1_migrations` table, so the deployment
workflow only applies pending migrations.
