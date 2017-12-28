package com.campusCloudStorage.service.impl;


import com.campusCloudStorage.dao.FileHeaderDao;
import com.campusCloudStorage.dao.UserFileShareDao;
import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.enums.CreateStateEnum;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.UpdateStateEnum;
import com.campusCloudStorage.service.FileHeaderService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.File;
import java.util.Date;
import java.util.List;

@Service("fileHeaderService")
public class FileHeaderServiceImpl implements FileHeaderService{

    @Resource
    private FileHeaderDao fileHeaderDao;

    @Resource
    private UserFileShareDao userFileShareDao;


    @Override
    public CreateStateEnum createFileHeader(FileHeader fileHeader) {
        if(fileHeader==null){
            return CreateStateEnum.FAILED;
        }

        List<FileHeader> siblings=fileHeaderDao.selectByParentId(fileHeader.getParent());
        if(siblings!=null){
            for (FileHeader sibling:siblings){
                //如果当前目录下有同名文件，则删除。
                if(sibling.getName().equals(fileHeader.getName())){
                    fileHeaderDao.deleteByPrimaryKey(sibling.getfId());
                    userFileShareDao.deleteByFId(sibling.getfId());
                    //TODO
                }
            }
        }


        fileHeader.setSubmitTime(new Date());
        fileHeaderDao.insert(fileHeader);
        return CreateStateEnum.SUCCESS;
    }

    @Override
    public DeleteStateEnum deleteFileHeader(int fId) {
        FileHeader fileHeader= getFileHeaderById(fId);

        File file = new File(fileHeader.getPath());
        if(file.exists()){
            file.delete();
        }

        userFileShareDao.deleteByFId(fId);
        int deleteCount=fileHeaderDao.deleteByPrimaryKey(fId);
        if(deleteCount==1){
            return DeleteStateEnum.SUCCESS;
        }
        return DeleteStateEnum.FAILED;
    }

    @Override
    public FileHeader getFileHeaderById(int fId) {
        return fileHeaderDao.selectByPrimaryKey(fId);
    }

    @Override
    public UpdateStateEnum updateFileHeader(FileHeader fileHeader) {
        if(fileHeader==null){
            return UpdateStateEnum.FAILED;
        }
        int updateCount = fileHeaderDao.updateByPrimaryKey(fileHeader);
        if(updateCount==1){
            return UpdateStateEnum.SUCCESS;
        }
        return UpdateStateEnum.FAILED;
    }
}
