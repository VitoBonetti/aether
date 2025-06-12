import git


def check_for_update():
    try:
        repo = git.Repo(search_parent_directories=True)
        origin = repo.remote('origin')
        origin.fetch()

        ahead = sum(1 for _ in repo.iter_commits("HEAD..origin/master"))
        if ahead > 0:
            return ahead
        else:
            return 0
    except Exception as e:
        print(e)
        return 0
