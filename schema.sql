CREATE TABLE IF NOT EXISTS scansioni (
    idScan INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    status TEXT CHECK(status IN ('pending', 'processing', 'done', 'error')) NOT NULL DEFAULT 'pending',
    pathOutput TEXT,
    timestampStart DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestampEnd DATETIME
);
