-- Daily cleanup of refresh tokens that are older than 60 days
select cron.schedule(
    'daily-cleanup',
    '30 3 * * *', -- every day at 3:30am (GMT)
    $$
    delete from refresh_sessions where created_at < now() - interval '60 days' or revoked = true;
    $$
);
