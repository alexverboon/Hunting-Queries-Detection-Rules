\_SentinelHealth()

| where OperationName in ("Scheduled analytics rule run","NRT analytics rule run")

| summarize Count=count() by Reason, Status



\_SentinelHealth()

| where OperationName in ("Scheduled analytics rule run","NRT analytics rule run")

| where Status in ("Failure","Warning")

| summarize RunCount=count() by SentinelResourceId, RuleName=SentinelResourceName,Status

| order by RunCount desc, Status asc



\_SentinelHealth()

| where OperationName in ("Scheduled analytics rule run","NRT analytics rule run")

| where Status in ('Failure', 'Warning')

| project TimeGenerated, RuleName=SentinelResourceName, Status, Description, Reason, Type=SentinelResourceKind

| order by TimeGenerated desc

