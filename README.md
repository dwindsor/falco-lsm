# lsm-plugin
A Falco plugin for processing events from the LSM subsystem.

## Sample Rules

```yaml
- rule: A program is executed by root
  condition: lsm.etype in (exec) and lsm.user.uid=root
  desc: This rule logs all programs executed by root
  output: "[lsm] exec path=%lsm.file.path dev=%lsm.file.device ino=%lsm.file.inode uid=%lsm.user.uid gid=%lsm.user.gid"
  priority: INFO
  source: lsm
  tags: [lsm]
```

## Output

```bash
00:32:56.650303000: Informational [lsm] exec path=/bin/getent dev=0 ino=4876 uid=root gid=root
00:32:56.650326000: Informational [lsm] exec path=/usr/sbin/groupadd dev=0 ino=48310 uid=root gid=root
00:32:56.711923000: Informational [lsm] exec path=/usr/sbin/sss_cache dev=0 ino=48538 uid=root gid=root
00:32:56.714184000: Informational [lsm] exec path=/usr/sbin/sss_cache dev=0 ino=48538 uid=root gid=root
00:32:56.744491000: Informational [lsm] exec path=/bin/getent dev=0 ino=4876 uid=root gid=root
00:32:56.746713000: Informational [lsm] exec path=/usr/sbin/useradd dev=0 ino=48571 uid=root gid=root
00:32:56.807931000: Informational [lsm] exec path=/usr/sbin/sss_cache dev=0 ino=48538 uid=root gid=root
00:32:56.810157000: Informational [lsm] exec path=/usr/sbin/sss_cache dev=0 ino=48538 uid=root gid=root
```
