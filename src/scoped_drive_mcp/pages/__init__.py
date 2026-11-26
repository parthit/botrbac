"""The dashboard's pages, one module per group of routes.

Each module has one function that takes the shared `Kit` (kit.py) and returns its
handlers. `build_dashboard` in dashboard.py calls them and owns the route table, so the
order routes are matched in is written in one place.
"""
