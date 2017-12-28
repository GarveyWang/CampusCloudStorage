package com.campusCloudStorage.service.impl;

import com.campusCloudStorage.dao.DirDao;
import com.campusCloudStorage.dao.FileHeaderDao;
import com.campusCloudStorage.entity.Dir;
import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.enums.CreateStateEnum;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.UpdateStateEnum;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.*;

@Service("dirService")
public class DirServiceImpl implements com.campusCloudStorage.service.DirService{

    @Resource
    private DirDao dirDao;

    @Resource
    private FileHeaderDao fileHeaderDao;

    @Override
    public CreateStateEnum createDir(Dir dir) {
        //若创建信息不完整，创建失败，返回
        if(dir==null || dir.getParent()==null||
                dir.getName()==null||"".equals(dir.getName().trim())){
            return CreateStateEnum.IMCOMPLETE;
        }

        //若创建信息包括非法字符，创建失败，返回
        if(dir.getName().contains("/")||dir.getName().contains("\\")){
            return CreateStateEnum.ILLEGAL_INFO;
        }

//        //当前父目录下若具有重命文件夹，创建失败，返回
//        List<Dir>childrenDirList=dirDao.selectByParentId(dir.getdId());
//        for(Dir childrenDir:childrenDirList){
//            if(childrenDir.getName().equals(dir.getName())){
//                return CreateStateEnum.DIR_NAME_REPEAT;
//            }
//        }

        //开始插入文件夹记录
        dir.setCreateTime(new Date());
        int insertCount=dirDao.insert(dir);
        if(insertCount==1){
            return CreateStateEnum.SUCCESS;
        }
        return CreateStateEnum.FAILED;
    }

    @Override
    public UpdateStateEnum updateDir(Dir dir) {
        //若更新信息不完整，更新失败，返回
        if(dir==null||dir.getName()==null||"".equals(dir.getName().trim())
                ||dir.getParent()==null || dir.getdId()==null) {
            return UpdateStateEnum.FAILED;
        }

        //若更新信息包括非法字符，更新失败，返回
        if(dir.getName().contains("/")||dir.getName().contains("\\")){
            return UpdateStateEnum.FAILED;
        }

//        //当前父目录下若具有重命文件夹，更新失败，返回
//        List<Dir>siblings= getSiblingDirs(dir);
//        for (Dir sibling:siblings){
//            if(sibling.getName().equals(dir.getName())){
//                return UpdateStateEnum.FAILED;
//            }
//        }

        //开始更新
        int updateCount=dirDao.updateByPrimaryKeySelective(dir);
        if(updateCount==1){
            return UpdateStateEnum.SUCCESS;
        }
        return UpdateStateEnum.FAILED;
    }

    //删除文件夹，需要考虑到其所有的子孙文件夹与文件。都需要删除，因此需要递归
    @Override
    public DeleteStateEnum deleteDirById(int dId) {
        //如果无此文件夹，返回删除失败
        Dir dir = dirDao.selectByPrimaryKey(dId);
        if(dir==null){
            return DeleteStateEnum.FAILED;
        }

        //删除该文件夹下的第一代子文件
        List<FileHeader> firstChildrenFileHeaderList= getFirstChildrenFileHeaders(dId);
        if(firstChildrenFileHeaderList!=null){
            for (FileHeader fileHeader: firstChildrenFileHeaderList){
                fileHeaderDao.deleteByPrimaryKey(fileHeader.getfId());
            }
        }

        List<Dir> firstChildrenDirList= getFirstChildrenDirs(dId);
        if(firstChildrenDirList!=null){
            for(Dir child:firstChildrenDirList){
                deleteDirById(child.getdId());
                dirDao.deleteByPrimaryKey(child.getdId());
            }
        }
        dirDao.deleteByPrimaryKey(dId);
        return DeleteStateEnum.SUCCESS;
    }

    @Override
    public Dir getDirById(int dId) {
        Dir dir = dirDao.selectByPrimaryKey(dId);
        return dir;
    }

    @Override
    public Dir getDirWithFirstChildrenById(int dId) {
        Dir dir = dirDao.selectByPrimaryKey(dId);
        if(dir!=null){
            List<Dir>childrenDirList=dirDao.selectByParentId(dId);
            List<FileHeader>childrenFileList=fileHeaderDao.selectByParentId(dId);

            dir.setChildrenDirList(childrenDirList);
            dir.setChildrenFileHeaderList(childrenFileList);
        }
        return dir;
    }

    @Override
    public List<Dir> getFirstChildrenDirs(int dId) {
        List<Dir>childrenDirList=dirDao.selectByParentId(dId);
        return childrenDirList;
    }

    @Override
    public List<FileHeader> getFirstChildrenFileHeaders(int dId) {
        List<FileHeader>childrenFileList=fileHeaderDao.selectByParentId(dId);
        return childrenFileList;
    }

    @Override
    public Dir getDirWithAllChildren(int dId) {
        Dir rootDir= dirDao.selectByPrimaryKey(dId);
        if(rootDir!=null){
            List<Dir> firstChildrenDirList=dirDao.selectByParentId(dId);
            if(firstChildrenDirList!=null){
                int len=firstChildrenDirList.size();
                for(int i=0;i<len;++i){
                    Dir dir=firstChildrenDirList.get(i);
                    dir.setChildrenDirList(getDirWithAllChildren(dir.getdId()).getChildrenDirList());
                }
                rootDir.setChildrenDirList(firstChildrenDirList);
            }
            List<FileHeader> firstChildrenFileHeaderList=fileHeaderDao.selectByParentId(dId);
            rootDir.setChildrenFileHeaderList(firstChildrenFileHeaderList);
        }
        return rootDir;
    }

    @Override
    public List<Dir> getSiblingDirs(Dir dir) {
        Dir parentDir= getDirWithFirstChildrenById(dir.getParent());
        List<Dir>siblingsDirList=null;
        if(parentDir!=null){
            siblingsDirList=parentDir.getChildrenDirList();
            for (Iterator<Dir> iterator=siblingsDirList.iterator();iterator.hasNext();){
                if(iterator.next().getdId()==dir.getdId()){
                    iterator.remove();
                }
                break;
            }
        }
        return siblingsDirList;
    }

    @Override
    public List<Dir> getPathList(Dir dir) {
        List<Dir>path=new ArrayList<>();
        Dir currentDir=dir;
        path.add(currentDir);
        while (currentDir.getParent()!=null){
            currentDir= getDirById(currentDir.getParent());
            path.add(currentDir);
        }
        Collections.reverse(path);
        return path;
    }
}
