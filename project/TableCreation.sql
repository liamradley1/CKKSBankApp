use testdb;
drop table transactions;
drop table direct_debits;
drop table accounts;

create table accounts(
id integer primary key auto_increment,
firstName varchar(50) not null,
lastName varchar(50) not null, 
balance integer not null,
overdraft integer not null,
pin BIGINT not null
);

create table transactions(
transactionID int primary key auto_increment,
transactionTime BIGINT,
transactionType varchar(50) not null,
amount integer not null,
transactionOwnerID integer not null,
otherAccountID integer not null,
foreign key (transactionOwnerID) references accounts(id),
foreign key (otherAccountID) references accounts(id)
);

create table direct_debits(
debitID int primary key auto_increment,
transactionOwnerID int,
otherAccountID int,
amount int,
regularity varchar(50),
timeSet BIGINT,
foreign key (transactionOwnerID) references accounts(id),
foreign key (otherAccountID) references accounts(id)
);

insert into accounts(
firstName,
lastName, 
balance, 
overdraft, 
pin)
values ('Liam', 'Radley', 2000, 0, 7359067979067344955);

insert into accounts(
firstName,
lastName, 
balance, 
overdraft, 
pin)
values ('Aaron', 'Radley', 2000, 0, 7359067979067344955);

select * from transactions;
select * from accounts;
select * from direct_debits;
