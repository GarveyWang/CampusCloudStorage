package com.campusCloudStorage.service.impl;

import com.campusCloudStorage.entity.Dir;
import com.campusCloudStorage.enums.CreateStateEnum;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.UpdateStateEnum;
import com.campusCloudStorage.service.DirService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.annotation.Resource;

import java.util.List;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration({
        "classpath:spring/spring-dao.xml",
        "classpath:spring/spring-service.xml"})
public class DirServiceImplTest {
    @Resource
    private DirService dirService;

    @Test
    public void createDir() throws Exception {
        Dir dir=new Dir();
        dir.setName("haha");
        dir.setParent(3);
        CreateStateEnum createDirStateEnum = dirService.createDir(dir);
        System.out.println(createDirStateEnum.getStateInfo());
    }

    @Test
    public void selectWithAllChildrenById() throws Exception{
        Dir dir=dirService.getDirWithAllChildren(1);
        List<Dir> children=dir.getChildrenDirList();
        for(Dir child:children){
            System.out.println(child.getName());
        }
    }

    @Test
    public void getSiblingsDirList() throws Exception {
//        List<Dir> siblings=dirService.getSiblingDirs(3);
//        for (Dir dir:siblings){
//            System.out.println(dir.getName());
//        }
    }

    @Test
    public void update() throws Exception {
        Dir dir=new Dir();
        dir.setdId(5);
        dir.setName("haha");
        dir.setParent(3);
        UpdateStateEnum updateState=dirService.updateDir(dir);
        System.out.println(updateState.getStateInfo());
    }

    @Test
    public void deleteByPrimaryKey() throws Exception {
        DeleteStateEnum deleteState=dirService.deleteDirById(3);
        System.out.println(deleteState.getStateInfo());
    }

    @Test
    public void d() throws Exception {
    }
}