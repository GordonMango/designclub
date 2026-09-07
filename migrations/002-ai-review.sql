-- Cached AI role suggestions, so re-opening an application does not re-run the model.
ALTER TABLE applications ADD COLUMN ai_review TEXT;
ALTER TABLE applications ADD COLUMN ai_reviewed_at TEXT;
