import git


def check_for_update():
    print("Checking for updates...")
    try:
        repo = git.Repo(search_parent_directories=True)
        print(f"Repo found! {repo}")
        origin = repo.remote('origin')
        origin.fetch()

        ahead = sum(1 for _ in repo.iter_commits("HEAD..origin/master"))
        print(ahead)
        if ahead > 0:
            return ahead
        else:
            print("No updates detected!")
            return 0
    except Exception as e:
        print(e)
        return 0
