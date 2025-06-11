import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class State:
    def __init__(self):
        self.data_source_dir = f"{project_root}/data_source"
        self.data_analysis_dir = f"{project_root}/data_analysis"
        self.web_pages_dir = f"{project_root}/src/assets/web"
