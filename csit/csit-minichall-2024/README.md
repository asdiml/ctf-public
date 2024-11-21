# CSIT Mini-Challenge 2024

Cloud Development Mini-Challenge

## Task 1

First, we are told to create the following k8 deployment

```
kubectl create deployment investigation-unit --image=sachua/task-1:v0.0.1
```

We are literally given the command to run to obtain the flag

```
controlplane $ kubectl logs -n default deployment/investigation-unit
THE WEAPON IS A: Katana
```

so the first flag is "Katana". 

## Task 2

We need to create a k8 deployment again

```
kubectl create deployment analysis-unit --image=sachua/task-2:v0.0.1
```

but this time, we need to mount the `/mnt/data` directory onto the container, so we run the command

```
kubectl edit deployment analysis-unit
```

which throws us into a Vim editor of the deployment yaml file. We edit the `spec.template.spec` portion of the file as follows

```diff
     spec:
       containers:
       - image: sachua/task-2:v0.0.1
         imagePullPolicy: IfNotPresent
         name: task-2
+        volumeMounts:
+        - name: data-volume
+          mountPath: /mnt/data
         resources: {}
         terminationMessagePath: /dev/termination-log
         terminationMessagePolicy: File
+      volumes:
+      - name: data-volume
+        hostPath:
+          path: /mnt/data
+          type: Directory
```

where the `name` field is for matching of `volumeMounts` in the container to `volumes` on the host. We are once again provided with the command to get the flag, which we run

```
controlplane $ kubectl logs -n default deployment/analysis-unit | sed 1d | md5sum | awk '{print $1}'
c33b083af53411171863163a79f6450c
```

For some context, the log contains the following text: 

```
THE FINGERPRINT IS: 
...............................,,;+*?%S#@@@@@@@@@@@@#S%?*;,...............................
..........................,:+?S#@@@@@#S%%??******??%%S#@@#:..,;;:,........................
........................+S@@@@#%*+:,...................,,,...;@@@#%*:.....................
........................+S%+:,.....:+*?%SS########S%%?*+:,,...,;*%@@S,....................
............................,;+:...%@@##S%%%%??%%%SS#@@@@@#S?+:...,:,.....................
........................,;*S@@@%...,,,...............,,:;*?S@@@@%*:.......................
.....................,+%@@@#%+:....,:;+*?%%SSSSSS%%*,.......,:+%#@@#?;,...................
...................;?@@@S*:...,;*%#@@@@@##SS%%%%SS#S,..;#S%+:,..,;*#@@#*:.................
................,+S@@#*:...;*S@@@#%?+;,,,..............:?S@@@@S*:...:?#@@%;...............
...............+#@@%;...;?#@@#?+:....,:...,*%%%%%?*+;:,....:+%@@@S*:..,+S@@S:.............
.............;S@@%:..,+S@@#*:...,;?S#@@?..,%######@@@@@#%*;,..,;?#@*.....+%S:.............
............;@@S;..,*#@@%;,..:*S@@@#%*;,..........,,:+*%#@@@S+:..,,...::..................
............,;;,..+#@@?:....+@@#?;,...,:;+*+,..,+*;:,....:+%@@@S+,...;@@S;................
................:%@@%:..,;:.,;:...,+?S@@@@@#,..;#@@@@#S?:...,+S@@#*,..;S@@?,..............
...............;#@#+..,*@@S....,*S@@@S?+;:,......,:;*%##+......:?@@#+..,*@@S:.............
..............*@@S:..;S@@?,..:%@@@%+,...,:;+***++;:,...,..,?S*:..:%@@%,..;@@#;............
.............*@@S,..+@@#;..:?@@#+,..,+?#@@@@@@@@@@@@S?;,...*@@@*,..+@@#;..:#@@;...........
............;@@S,..*@@%,..+#@@*,..;%@@@S?+::,,,,:;+%#@@#?:..,?@@S:..:#@@;..:@@#:..........
...........,#@#:..+@@%,..*@@S:..;S@@S+,...,:;;;;:,...:*#@@?,..;#@@;..:#@@:..+@@?..........
...........?@@+..:@@#,..*@@%,..*@@#;...;?#@@@@@@@@S?:..,*@@#;..:#@@;..;@@S,..:;,..........
..........:@@#,..%@@;..;@@S,..?@@%,..+#@@S*;::::+?#@@%:..:#@@+..:@@#,..?@@+...............
..........+@@*..:@@S...S@@;..+@@%...?@@S:...:::,..,+#@@+..:#@@:..*@@*..:@@S...............
..........%@@;..+@@*..:@@S..,S@@:..*@@%..,*#@@@@S;..,#@@:..+@@?..,@@#...S@@:..............
..........*#S,..?@@+..+@@?..:@@S...#@@,..*@@%;;S@@;..+@@?..:@@S...S@@,..%@@;..............
...........,,...?@@;..:%S;..:@@S..,#@@,..%@@:..*@@*..;@@%..,@@#...S@@:..?@@;..............
................?@@;........:@@S..,#@@,..%@@:..*@@*..;@@?..,@@#...S@@:..?@@;..............
................?@@;..:%S;..:@@S..,#@@,..%@@:..*@@*..;@@?..,@@#...S@@:..%@@;..............
...............,S@@:..*@@*..:@@%..,#@#,..%@@:..*@@*..;@@?..,@@#...S@@:..+##:..............
.............,+#@@*..,#@@:..*@@*..:@@S...#@@,..?@@+..+@@?..:@@S..,S@#,...,,...............
.............+@@%:..:S@@+..,#@@,..*@@*..:@@S...S@@:..*@@+..;@@%..,@@#,....................
.............,::..,*@@#+..,S@@+..:@@#,..?@@+..:@@S,..S@@:..*@@*..;@@%.....................
................,+#@@?,..;#@@+..,S@@;..;@@S,..?@@*..:@@S...S@@:..,?%:.....................
................?@@%:..:?@@S;..:S@@+..:#@@:..:@@#,..%@@+..;@@%............................
................:;:..,*@@#*,..+@@#;..:#@@;..,S@@;..;@@S,..%@@;..:?*,......................
....................+#@@?,..;S@@%:..;#@@;..,%@@*..,#@@:..+@@%..,S@@:......................
....................;%?:..:%@@S;..,*@@S:..,%@@?..,%@@+..:#@#:..*@@?.......................
........................,?@@#+,..+#@@?,..:S@@*..,%@@*..,S@@;..;@@#,.......................
........................;##*,..;S@@%:...+#@#+..,S@@*..,%@@*...+##;........................
.........................,,..:%@@S;...:%@@%:..;#@@+..,%@@*.....,,.........................
...........................,?@@#+,..:?@@#+..,*@@#;..:S@@*.................................
...........................*@#*,..,*@@#*,..;S@@?,..+@@#;..................................
............................:,..,+#@@?,..:%@@S;..,%@@%:...................................
...............................,S@@%:..:?@@#+..,*#@@*.....................................
................................;+:..,?@@#*,..+S@@%:......................................
.....................................;@@?,...,S@S;........................................
```

which we are simply taking the MD5 hash of (ignoring the first line). 

The second flag is "c33b083af53411171863163a79f6450c". 

## Task 3

We need to create a k8 deployment that will interact with the 2 deployments created in Tasks 1 and 2. First, we expose port 80 for the previous deployments

```
kubectl expose deployment investigation-unit --type=LoadBalancer --port=80
kubectl expose deployment analysis-unit --type=LoadBalancer --port=80
```

Then we create the deployment for this task

```
kubectl create deployment command-center --image=sachua/task-3:v0.0.1
```

and edit the deployment by editing the `spec.template.spec.containers` section of the yaml file

```diff
    spec:
      containers:
      - image: sachua/task-3:v0.0.1
        imagePullPolicy: IfNotPresent
        name: task-3
+       ports: 
+       - containerPort: 80
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      terminationGracePeriodSeconds: 30
```

We are once again provided with the command to get the flag, which we run

```
controlplane $ kubectl logs -n default deployment/command-center | grep -im 1 culprit | sed 's/.*: //'
Tan Ah Kow
```

so the final flag is "Tan Ah Kow". 