CREATE DATABASE bankDB;
use bankDB;
drop table direct_debits;
drop table transactions;
drop table accounts;

create table accounts(
id integer primary key auto_increment,
firstName varchar(50) not null,
lastName varchar(50) not null, 
balanceAddress tinytext not null,
keyAddress tinytext not null,
overdraft double not null,
pin BIGINT not null
);

insert into accounts(
firstName, 
lastName, 
balanceAddress, 
keyAddress, 
overdraft, 
pin)
values ('Bank Of', 'Radley', 'admin.txt', 'privateKeyCKKS.pem', 0, 7359067979067344955);

insert into accounts(
firstName, 
lastName, 
balanceAddress, 
keyAddress, 
overdraft, 
pin)
values ('Liam', 'Radley', 'testCipher1.txt', 'privateKeyCKKS.pem', 1000, 7359067979067344955);

insert into accounts(
firstName,
lastName,
balanceAddress,
keyAddress,
overdraft,
pin)
values ('Aaron', 'Radley', 'testCipher2.txt', 'privateKeyCKKS.pem', 1000, 7359067979067344955);

create table transactions(
transactionID int primary key auto_increment,
transactionTime BIGINT not null,
transactionType varchar(50) not null,
amount VARCHAR(100) not null,
transactionOwnerID integer not null,
otherAccountID integer,
foreign key (transactionOwnerID) references accounts(id),
foreign key (otherAccountID) references accounts(id)
);

create table direct_debits(
debitID int primary key auto_increment,
transactionOwnerID int not null,
otherAccountID int not null,
amount varchar(100) not null,
regularity varchar(50) not null,
timeSet BIGINT not null,
foreign key (transactionOwnerID) references accounts(id),
foreign key (otherAccountID) references accounts(id)
);

select * from accounts;
select * from transactions;
select * from direct_debits;