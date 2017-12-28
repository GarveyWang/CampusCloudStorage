-- MySQL dump 10.13  Distrib 5.7.17, for Win64 (x86_64)
--
-- Host: localhost    Database: cloud_storage
-- ------------------------------------------------------
-- Server version	5.7.17

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `dir`
--

DROP TABLE IF EXISTS `dir`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `dir` (
  `d_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(32) NOT NULL,
  `create_time` datetime NOT NULL,
  `parent` int(11) DEFAULT NULL,
  PRIMARY KEY (`d_id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dir`
--

LOCK TABLES `dir` WRITE;
/*!40000 ALTER TABLE `dir` DISABLE KEYS */;
INSERT INTO `dir` VALUES (1,'root','2017-12-16 11:33:51',NULL),(2,'root','2017-12-16 12:04:38',NULL),(3,'recyclebin','2017-12-18 14:00:44',NULL),(4,'recyclebin','2017-12-18 14:00:44',NULL),(5,'recyclebin','2017-12-18 14:00:44',NULL),(6,'recyclebin','2017-12-18 14:00:44',NULL),(7,'recyclebin','2017-12-18 14:00:44',NULL),(13,'文件夹1','2017-12-16 22:57:12',1),(15,'文件夹1-1','2017-12-17 00:02:39',13),(16,'文件夹1-2','2017-12-17 00:02:47',13),(18,'root','2017-12-18 14:00:44',NULL),(19,'root','2017-12-18 14:00:44',NULL),(20,'root','2017-12-18 14:00:44',NULL),(22,'文件夹3','2017-12-23 01:07:11',1);
/*!40000 ALTER TABLE `dir` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `file_header`
--

DROP TABLE IF EXISTS `file_header`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `file_header` (
  `f_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(32) NOT NULL,
  `path` varchar(255) NOT NULL,
  `size` int(11) NOT NULL,
  `submit_time` datetime NOT NULL,
  `parent` int(11) DEFAULT NULL,
  `u_id` int(11) NOT NULL,
  PRIMARY KEY (`f_id`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `file_header`
--

LOCK TABLES `file_header` WRITE;
/*!40000 ALTER TABLE `file_header` DISABLE KEYS */;
INSERT INTO `file_header` VALUES (23,'啊啊.txt','G:\\code\\CampusCloudStorage\\target\\CampusCloudStorage\\2\\2004316862啊啊.txt',3,'2017-12-21 13:06:45',2,2),(25,'啊啊.txt','G:\\code\\CampusCloudStorage\\target\\CampusCloudStorage\\1\\2133350742啊啊.txt',3,'2017-12-23 00:57:19',3,1);
/*!40000 ALTER TABLE `file_header` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `group_file_share`
--

DROP TABLE IF EXISTS `group_file_share`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `group_file_share` (
  `g_id` int(11) NOT NULL,
  `provider_id` int(11) NOT NULL,
  `f_id` int(11) NOT NULL,
  `remark` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`g_id`,`provider_id`,`f_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `group_file_share`
--

LOCK TABLES `group_file_share` WRITE;
/*!40000 ALTER TABLE `group_file_share` DISABLE KEYS */;
/*!40000 ALTER TABLE `group_file_share` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `group_member`
--

DROP TABLE IF EXISTS `group_member`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `group_member` (
  `g_id` int(11) NOT NULL,
  `u_id` int(11) NOT NULL,
  `permitted` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`g_id`,`u_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `group_member`
--

LOCK TABLES `group_member` WRITE;
/*!40000 ALTER TABLE `group_member` DISABLE KEYS */;
/*!40000 ALTER TABLE `group_member` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `u_id` int(11) NOT NULL,
  `password` varchar(16) NOT NULL,
  `name` varchar(64) NOT NULL,
  `root_dir` int(11) NOT NULL,
  `recyclebin` int(11) NOT NULL,
  `type` varchar(8) NOT NULL DEFAULT 'PRIVATE',
  PRIMARY KEY (`u_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,'1','王二狗',1,3,'PRIVATE'),(2,'2','马兰花',2,4,'PRIVATE'),(3,'3','李马哥',18,5,'PRIVATE'),(4,'4','林马蛋',19,6,'PRIVATE'),(5,'5','李五',20,7,'PRIVATE');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_file_share`
--

DROP TABLE IF EXISTS `user_file_share`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_file_share` (
  `from_id` int(11) NOT NULL,
  `to_id` int(11) NOT NULL,
  `f_id` int(11) NOT NULL,
  `remark` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`from_id`,`f_id`,`to_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_file_share`
--

LOCK TABLES `user_file_share` WRITE;
/*!40000 ALTER TABLE `user_file_share` DISABLE KEYS */;
/*!40000 ALTER TABLE `user_file_share` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_friend`
--

DROP TABLE IF EXISTS `user_friend`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_friend` (
  `from_id` int(11) NOT NULL,
  `to_id` int(11) NOT NULL,
  `permitted` tinyint(4) NOT NULL,
  PRIMARY KEY (`from_id`,`to_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_friend`
--

LOCK TABLES `user_friend` WRITE;
/*!40000 ALTER TABLE `user_friend` DISABLE KEYS */;
INSERT INTO `user_friend` VALUES (1,2,1),(1,3,0),(2,3,1);
/*!40000 ALTER TABLE `user_friend` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_group`
--

DROP TABLE IF EXISTS `user_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_group` (
  `g_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) NOT NULL,
  `type` varchar(8) NOT NULL DEFAULT 'PRIVATE',
  `builder_id` int(11) NOT NULL,
  PRIMARY KEY (`g_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_group`
--

LOCK TABLES `user_group` WRITE;
/*!40000 ALTER TABLE `user_group` DISABLE KEYS */;
INSERT INTO `user_group` VALUES (2,'群组2','PRIVATE',2),(3,'群组3','PUBLIC',2);
/*!40000 ALTER TABLE `user_group` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-12-23  1:44:53
