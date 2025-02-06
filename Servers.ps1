$servers = 127.0.0.1

foreach ($server in $servers) {
    $tasks = get-scheduledtask -cimsession $server -TaskPath "" | Where-Object taskname -notmatch 'shadowcopy|user_feedsync|Google|optimize' | Select-Object pscomputername,TaskName, @{Name="Run As";Expression={ $.principal.userid }},state
    $tasks| convertto-csv -NoTypeInformation | select-object -skip 1 | out-file ".\scheduledtasks.csv" -append
}
