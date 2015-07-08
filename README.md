This Application is a Host node that connect to an AS2805 interface link, typically a bank / switch of an aquirer.
Here are the steps to get it working:
1. use python 2.7
  and a Thales 9000 HSM

2. install the database scripts.
3. configure a host in the databse.
4. generate your switch keys, and update them in the database
5. get your keys from your host and insert them into the database.

start your HostNode.py to initiate the logon and key exchange sequence.

when you want to send a transaction, insert a record into the cuscal_host table i.e. 0200 request.
the service will buid a AS2805 object and send it to your host for approval.


easy as pie!
