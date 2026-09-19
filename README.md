# AeroDrift

Responsive Flask CloudOps dashboard for the AeroDrift demo.

## Run

```powershell
python -m pip install -r requirements.txt
python web_app.py
```

Open `http://127.0.0.1:5000`.

## Authentication

Use **Sign Up** to create a local demo account. Users are stored in `data/auth.db`. Dashboard, topology, drift, remediation, history, reports and API routes require a logged-in session.

## Topology

The interactive topology is generated from `data/mock_cloud.json` through NetworkX and rendered with Cytoscape.js. The mock file contains resources, security groups and explicit connections.

## Demo flow

1. Sign up or log in.
2. Open **Topology** to inspect the live graph.
3. Open **Drift Detection** to inspect Internet-to-private-database exposure.
4. Generate remediation.
5. Execute in demo/dry-run mode.
6. Refresh the topology to see the updated mock state.
