-- This project is a personal vault and permits exactly one user record.
-- Existing databases with more than one record are left intact, but no
-- additional users can be inserted after this trigger is installed.
CREATE TRIGGER IF NOT EXISTS users_single_user_before_insert
BEFORE INSERT ON users
WHEN EXISTS (SELECT 1 FROM users)
BEGIN
    SELECT RAISE(ABORT, 'single-user vault already has an account');
END;
