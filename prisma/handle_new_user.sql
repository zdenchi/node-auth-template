-- Create trigger for creating profile on user creation
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profile(id)
  values (new.id);
  return new;
end;
$$ language plpgsql;
